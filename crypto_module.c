/*
 * Author: Ken Chow
 * Email : kenchow.cn@gmail.com
 * Date  : 2016-4-11
 * This module offered a few interfaces for implementing RSA and AES in FIPS openssl mode.
 */
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto_module.h"

#define __DEBUG__

#ifdef __DEBUG__
#define DEBUG_INFO(format,...) printf("File: "__FILE__", Line: %05d -> "format"\n", \
__LINE__, ##__VA_ARGS__)
#else
#define DEBUG_INFO(format,...)
#endif

int CRYPTO_mode_init()
{
#ifdef OPENSSL_FIPS
    if(!FIPS_mode_set(1))
    {
        fprintf(stderr, "MSG: \n");
        ERR_load_crypto_strings();
        ERR_print_errors_fp(stderr);
        return -1;
    }
    else
        fprintf(stderr,"*** IN FIPS MODE ***\n");
#else
    fprintf(stderr, "NO DEFINE_FIPS !\n");
#endif
    return 0;
}

int CRYPTO_RSA_keys_generate(RSA_KEY_INFO_T *key_t)
{
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;

    /*
     * 1. CA needs the key length more than 2048.
     * 2. If the length too long may not suitable for cell phones.
     */
    if ((RSA_MIN_KEY_BITS > (key_t->key_bits)) \
        || (RSA_MAX_KEY_BITS < (key_t->key_bits)))
    {
        DEBUG_INFO("RSA: args error.");
        return -1;
    }
#ifdef OPENSSL_FIPS
    bne = FIPS_bn_new();
#else
    bne = BN_new();
#endif
    if (1 != BN_set_word(bne, RSA_F4))
    {
        goto ERR;
    }

#ifdef OPENSSL_FIPS
    rsa = FIPS_rsa_new();
#else
    rsa = RSA_new();
#endif

#ifdef OPENSSL_FIPS
    if (1 != FIPS_rsa_generate_key_ex(rsa, key_t->key_bits, bne, NULL))
#else
        if (1 != RSA_generate_key_ex(rsa, key_t->key_bits, bne, NULL))
#endif
        {
            goto ERR;
        }

#ifdef OPENSSL_FIPS
    key_t->key_len = FIPS_rsa_size(rsa);
#else
    key_t->key_len = RSA_size(rsa);
#endif

    /* public key */
    memset(&key_t->public_key[0], 0, key_t->key_len);

#ifdef OPENSSL_FIPS
    FIPS_bn_bn2bin(rsa->n, &key_t->public_key[0]);
#else
    BN_bn2bin(rsa->n, &key_t->public_key[0]);
#endif
    /* private key */
    memset(&key_t->private_key[0], 0, key_t->key_len);

#ifdef OPENSSL_FIPS
    FIPS_bn_bn2bin(rsa->d, &key_t->private_key[0]);
#else
    BN_bn2bin(rsa->d, &key_t->private_key[0]);
#endif

    if (bne)
#ifdef OPENSSL_FIPS
        FIPS_bn_free(bne);
#else
    BN_free(bne);
#endif

    if (rsa)
#ifdef OPENSSL_FIPS
        FIPS_rsa_free(rsa);
#else
    RSA_free(rsa);
#endif
    return 0;
ERR:
    if (bne)
#ifdef OPENSSL_FIPS
        FIPS_bn_free(bne);
#else
    BN_free(bne);
#endif

    if (rsa)
#ifdef OPENSSL_FIPS
        FIPS_rsa_free(rsa);
#else
    RSA_free(rsa);
#endif
    return -1;
}

/*
 * This module is designed for concurrency, load key in each en/decrypt.
 */
static int RSA_load_keys(RSA_KEY_INFO_T *key, RSA *rsa)
{
    const unsigned char e[4] = "\x01\x00\x01";
#ifdef OPENSSL_FIPS
    rsa->n = FIPS_bn_bin2bn(key->public_key, key->key_len, rsa->n);
    rsa->e = FIPS_bn_bin2bn("\x01\x00\x01", 3, rsa->e);
    rsa->d = FIPS_bn_bin2bn(key->private_key, key->key_len, rsa->d);
#else
    rsa->n = BN_bin2bn(key->public_key, key->key_len, rsa->n);
    rsa->e = BN_bin2bn(e, 3, rsa->e);
    rsa->d = BN_bin2bn(key->private_key, key->key_len, rsa->d);
#endif
    return 0;
}

int CRYPTO_RSA_public_key_encrypt(const META_DATA_INFO_T *text_t, META_DATA_INFO_T *cipher_t, RSA_KEY_INFO_T *key_t)
{
    int flen, i;
    RSA *rsa = NULL;

    if ((NULL == text_t) || (NULL == cipher_t))
    {
        DEBUG_INFO("RSA: args error.");
        return -1;
    }

    if ((RSA_MIN_KEY_LEN > key_t->key_len) \
        || (RSA_MAX_KEY_LEN < key_t->key_len))
    {
        DEBUG_INFO("RSA: Illegal key length [%d].", key_t->key_len);
        return -1;
    }

#ifdef OPENSSL_FIPS
    rsa = FIPS_rsa_new();
#else
    rsa = RSA_new();
#endif
    if (NULL == rsa)
    {
        DEBUG_INFO("RSA: RSA_new error.");
        return -1;
    }

    RSA_load_keys(key_t, rsa);

#ifdef OPENSSL_FIPS
    flen = FIPS_rsa_size(rsa);
#else
    flen = RSA_size(rsa);
#endif

    unsigned char *text_tmp = (unsigned char *)text_t->addr;
    unsigned char *cipher_tmp = (unsigned char *)cipher_t->addr;
    cipher_t->len = 0;

    for (i=0; i<(text_t->len/flen)+1; i++)
    {

		printf("----------###%d cipher_t->len = %d#####################\n", i, cipher_t->len);
#ifdef OPENSSL_FIPS
        cipher_t->len += FIPS_rsa_public_encrypt(flen, text_tmp, cipher_tmp, rsa, RSA_NO_PADDING);
#else
        cipher_t->len += RSA_public_encrypt(flen, text_tmp, cipher_tmp, rsa, RSA_NO_PADDING);
#endif
        if (0 > cipher_t->len)
        {
            DEBUG_INFO("RSA: Error Number = 0x%lx", ERR_get_error());
#ifdef OPENSSL_FIPS
            FIPS_rsa_free(rsa);
#else
            RSA_free(rsa);
#endif
            return -1;
        }
        text_tmp+=flen;
        cipher_tmp+=flen;
    }

#ifdef OPENSSL_FIPS
    FIPS_rsa_free(rsa);
#else
    RSA_free(rsa);
#endif
	printf("----------###%d cipher_t->len = %d#####################\n", i, cipher_t->len);
	cipher_t->len = text_t->len;
    return 0;
}

int CRYPTO_RSA_private_key_decrypt(const META_DATA_INFO_T *cipher_t, META_DATA_INFO_T *text_t, RSA_KEY_INFO_T *key_t)
{
    int flen, i;
    RSA *rsa = NULL;

    if ((NULL == text_t) || (NULL == cipher_t))
    {
        DEBUG_INFO("RSA: args error.");
        return -1;
    }

    if ((RSA_MIN_KEY_LEN > key_t->key_len) \
        || (RSA_MAX_KEY_LEN < key_t->key_len))
    {
        DEBUG_INFO("RSA: Illegal key length.");
        return -1;
    }
#ifdef OPENSSL_FIPS
    rsa = FIPS_rsa_new();
#else
    rsa = RSA_new();
#endif
    if (NULL == rsa)
    {
        DEBUG_INFO("RSA: RSA_new error.");
        return -1;
    }

    RSA_load_keys(key_t, rsa);

#ifdef OPENSSL_FIPS
    flen = FIPS_rsa_size(rsa);
#else
    flen = RSA_size(rsa);
#endif

    unsigned char *cipher_tmp = (unsigned char*)cipher_t->addr;
    unsigned char *text_tmp = (unsigned char*)text_t->addr;
    int count = cipher_t->len/flen;
    text_t->len = 0;

    for (i=0; i<(count==0?1:count); i++)
    {
#ifdef OPENSSL_FIPS
        text_t->len += FIPS_rsa_private_decrypt(flen, cipher_tmp, text_tmp, rsa, RSA_NO_PADDING);
#else
        text_t->len += RSA_private_decrypt(flen, cipher_tmp, text_tmp, rsa, RSA_NO_PADDING);
#endif
        if (0 > text_t->len)
        {
            DEBUG_INFO("RSA: Error Number = 0x%lx", ERR_get_error());
#ifdef OPENSSL_FIPS
            FIPS_rsa_free(rsa);
#else
            RSA_free(rsa);
#endif
            return -1;
        }
        cipher_tmp+=flen;
        text_tmp+=flen;
    }
    text_t->len = cipher_t->len;
#ifdef OPENSSL_FIPS
    FIPS_rsa_free(rsa);
#else
    RSA_free(rsa);
#endif
    return 0;
}

int CRYPTO_AES_key_generate(AES_KEY_HANDLE_T *key_handle_t)
{
    unsigned char AesRandNum[AES_KEY_LEN] = {0};

    if (NULL == key_handle_t)
        return -1;

#ifdef OPENSSL_FIPS
    if (0 > FIPS_rand_pseudo_bytes(AesRandNum, sizeof(AesRandNum)))
#else
    if (0 > RAND_pseudo_bytes(AesRandNum, sizeof(AesRandNum)))
#endif
        {
            DEBUG_INFO("AES: RAND_pseudo_bytes.");
            return -1;
        }

    key_handle_t->key_len = AES_KEY_LEN;
    memcpy(&key_handle_t->key, AesRandNum, AES_KEY_LEN);

    return 0;
}

int CRYPTO_AES_init(AES_KEY_HANDLE_T *key_handle_t)
{
    if (NULL == key_handle_t)
        return -1;

#ifdef OPENSSL_FIPS
    FIPS_cipher_ctx_init(&key_handle_t->ctx);
#else
    EVP_CIPHER_CTX_init(&key_handle_t->ctx);
#endif
    return 0;
}

int CRYPTO_AES_release(AES_KEY_HANDLE_T *key_handle_t)
{
    if (NULL == key_handle_t)
        return -1;

#ifdef OPENSSL_FIPS
    FIPS_cipher_ctx_cleanup(&key_handle_t->ctx);
#else
    EVP_CIPHER_CTX_cleanup(&key_handle_t->ctx);
#endif

    return 0;
}

int CRYPTO_AES_encrypt(const META_DATA_INFO_T *text_t, META_DATA_INFO_T *cipher_t, AES_KEY_HANDLE_T *key_handle_t)
{
	unsigned char iv[sizeof(AES_IV)]= AES_IV;

    if(NULL == text_t || NULL == cipher_t || NULL == key_handle_t)
        return -1;

#ifdef OPENSSL_FIPS
    if (0 >= FIPS_cipherinit(&key_handle_t->ctx, FIPS_evp_aes_128_cfb128(), &key_handle_t->key[0], AES_IV, 1))
#else
    if (0 >= EVP_CipherInit(&key_handle_t->ctx, EVP_aes_128_cfb128(), &key_handle_t->key[0], iv, 1))
#endif
    {
        ERR_load_crypto_strings();
        ERR_print_errors_fp(stderr);
        return -1;
    }

#ifdef OPENSSL_FIPS
    FIPS_cipher(&key_handle_t->ctx, (unsigned char*)cipher_t->addr, (unsigned char*)text_t->addr, text_t->len);
#else
    EVP_Cipher(&key_handle_t->ctx, (unsigned char*)cipher_t->addr, (unsigned char*)text_t->addr, text_t->len);
#endif
    cipher_t->len = text_t->len;

	printf("----len---------%d %d----------------\n", cipher_t->len, text_t->len);

    return 0;
}

int CRYPTO_AES_decrypt(const META_DATA_INFO_T *cipher_t, META_DATA_INFO_T *text_t, AES_KEY_HANDLE_T *key_handle_t)
{
	unsigned char iv[sizeof(AES_IV)]= AES_IV;

    if(NULL == text_t || NULL == cipher_t || NULL == key_handle_t)
        return -1;

#ifdef OPENSSL_FIPS
    if (0 >= FIPS_cipherinit(&key_handle_t->ctx, FIPS_evp_aes_128_cfb128(), &key_handle_t->key[0], AES_IV, 0))
#else
        if (0 >= EVP_CipherInit(&key_handle_t->ctx, EVP_aes_128_cfb128(), &key_handle_t->key[0], iv, 0))
#endif
    {
        ERR_load_crypto_strings();
        ERR_print_errors_fp(stderr);
        return -1;
    }

#ifdef OPENSSL_FIPS
    FIPS_cipher(&key_handle_t->ctx, (unsigned char*)text_t->addr, (unsigned char*)cipher_t->addr, cipher_t->len);
#else
    EVP_Cipher(&key_handle_t->ctx, (unsigned char*)text_t->addr, (unsigned char*)cipher_t->addr, cipher_t->len);
#endif
    text_t->len = cipher_t->len;

    return 0;
}
