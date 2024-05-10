#include "common.h"

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "../argz/argz.h"
#include "../mud/aegis256/aegis256.h"

typedef struct cipher_interface{
    char name[20];

    size_t ABYTES;
    size_t NPUBBYTES;
    size_t KEYBYTES;

    int (*is_available)(void);
    void (*keygen)(unsigned char key[]);
    int (*encrypt)(unsigned char *c,
                    unsigned long long *clen_p,
                    const unsigned char *m,
                    unsigned long long mlen,
                    const unsigned char *ad,
                    unsigned long long adlen,
                    const unsigned char *nsec,
                    const unsigned char *npub,
                    const unsigned char *k);
} cipher_interface_t;


static cipher_interface_t aes_if = {
    "aes-gcm",
    crypto_aead_aes256gcm_ABYTES,
    crypto_aead_aes256gcm_NPUBBYTES,
    crypto_aead_aes256gcm_KEYBYTES,

    crypto_aead_aes256gcm_is_available,
    crypto_aead_aes256gcm_keygen,
    crypto_aead_aes256gcm_encrypt
};

static cipher_interface_t aegis_if = {
    "aegis256",
    crypto_aead_aegis256_ABYTES,
    crypto_aead_aegis256_NPUBBYTES,
    crypto_aead_aegis256_KEYBYTES,

    aegis256_is_available,
    crypto_aead_aegis256_keygen,
    crypto_aead_aegis256_encrypt
};

static cipher_interface_t chacha_if = {
    "chacha20poly1305",
    crypto_aead_chacha20poly1305_ABYTES,
    crypto_aead_chacha20poly1305_NPUBBYTES,
    crypto_aead_chacha20poly1305_KEYBYTES,

    NULL,
    crypto_aead_chacha20poly1305_keygen,
    crypto_aead_chacha20poly1305_encrypt
};

int
gt_bench(int argc, char **argv)
{
    struct argz bench_argz[] = {
        {"aes|chacha|aegis", NULL, NULL, argz_option},
        {NULL}};

    if (argz(bench_argz, argc, argv))
        return 1;

    if (sodium_init() == -1) {
        gt_log("sodium init failed\n");
        return 1;
    }

    cipher_interface_t *cipher_if;

    int term = isatty(1);
    
    cipher_if = argz_is_set(bench_argz, "aes")?&aes_if:
                argz_is_set(bench_argz, "aegis")?&aegis_if:&chacha_if;

    if (cipher_if == NULL) {
        gt_log("cipher_if is NULL\n");
        return 1;
    }

    if (cipher_if->is_available != NULL) {
        if (!cipher_if->is_available()) {
            gt_log("%s is not available on your platform\n", cipher_if->name);
            return 1;
        }
    }
    else if (cipher_if != &chacha_if) {
        gt_log("%s's cipher_if->is_available is NULL.\n", cipher_if->name);
        cipher_if = &chacha_if;
    }

    if (cipher_if->encrypt == NULL) {
        gt_log("%s's cipher_if->encrypt is NULL\n", cipher_if->name);
        return 1;
    }

    unsigned char buf[1450 + cipher_if->ABYTES];
    unsigned char nonce[cipher_if->NPUBBYTES];
    unsigned char key[cipher_if->KEYBYTES];

    unsigned long long ciphertext_len;
    
    if(cipher_if->keygen != NULL) {
        cipher_if->keygen(key);
    }
    else {
        gt_log("%s's cipher_if->keygen is null\n", cipher_if->name);
        return 1;
    }

    randombytes_buf(nonce, sizeof nonce); 
    memset(buf, 0, sizeof(buf));

    if (term) {
        printf("\ncipher: %s\n\n", cipher_if->name);
        printf("  size       min           mean            max      \n");
        printf("----------------------------------------------------\n");
    }

    int64_t size = 20;

    for (int i = 0; !gt_quit && size <= 1450; i++) {
        struct {
            int64_t min, mean, max, n;
        } mbps = { .n = 0 };

        int64_t bytes_max = (int64_t)1 << 24;

        while (!gt_quit && mbps.n < 10) {
            int64_t bytes = 0;
            int64_t base = (int64_t)clock();

            while (!gt_quit && bytes <= bytes_max) {
                cipher_if->encrypt(
                        buf, &ciphertext_len, buf, size, NULL, 0, NULL, nonce, key);

                bytes += size;
            }

            int64_t dt = (int64_t)clock() - base;
            bytes_max = (bytes * (CLOCKS_PER_SEC / 3)) / dt;
            int64_t _mbps = (8 * bytes * CLOCKS_PER_SEC) / (dt * 1000 * 1000);

            if (!mbps.n++) {
                mbps.min = _mbps;
                mbps.max = _mbps;
                mbps.mean = _mbps;
                continue;
            }

            if (mbps.min > _mbps)
                mbps.min = _mbps;

            if (mbps.max < _mbps)
                mbps.max = _mbps;

            mbps.mean += (_mbps - mbps.mean) / mbps.n;

            if (term) {
                printf("\r %5"PRIi64" %9"PRIi64" Mbps %9"PRIi64" Mbps %9"PRIi64" Mbps",
                        size, mbps.min, mbps.mean, mbps.max);
                fflush(stdout);
            }
        }

        if (term) {
            printf("\n");
        } else {
            printf("bench %s %"PRIi64" %"PRIi64" %"PRIi64" %"PRIi64"\n",
                    cipher_if->name, size, mbps.min, mbps.mean, mbps.max);
        }

        size += 2 * 5 * 13;
    }

    return 0;
}
