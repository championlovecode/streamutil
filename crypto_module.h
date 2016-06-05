#ifndef _CRYPTO_MODULE_H_
#define _CRYPTO_MODULE_H_

#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#undef OPENSSL_FIPS

/* define for RSA */
#define RSA_MIN_KEY_BITS 1024
#define RSA_MAX_KEY_BITS 4096
#define RSA_MIN_KEY_LEN (RSA_MIN_KEY_BITS/8)
#define RSA_MAX_KEY_LEN (RSA_MAX_KEY_BITS/8)
/* End of RSA */

/* define for AES */
#define AES_KEY_LEN 16 // 128bit
#define AES_MAX_KEY_LEN 32 //256bit
#define AES_IV "xpphoneaesivweng"
/* End of AES */

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct RSA_KEY_INFO_s
{
    int key_bits;
    int key_len;
    unsigned char public_key[RSA_MAX_KEY_LEN];
    unsigned char private_key[RSA_MAX_KEY_LEN];
}RSA_KEY_INFO_T;

typedef struct AES_KEY_HANDLE_s
{
    int key_len;
    unsigned char key[AES_MAX_KEY_LEN];
    EVP_CIPHER_CTX ctx;
}AES_KEY_HANDLE_T;

/* DATA */
/* if text longer than max encrypt text, we have to silce the raw text */
typedef struct META_DATA_INFO_s
{
    int len;
    void *addr;
}META_DATA_INFO_T;
/* End DATA */

int CRYPTO_mode_init();

///////////////////////////////////////////////////////////////////////////////////
/*
 * input : key_bits
 * output: key_len, public_key, private_key
 */
int CRYPTO_RSA_keys_generate(RSA_KEY_INFO_T *key_t);

/*
 * input : key_info_t, text_t
 * output: cipher_t
 */
int CRYPTO_RSA_public_key_encrypt(const META_DATA_INFO_T *text_t, META_DATA_INFO_T *cipher_t, RSA_KEY_INFO_T *key_t);

/*
 * input : key_info_t, cipher_t
 * output: text_t
 */
int CRYPTO_RSA_private_key_decrypt(const META_DATA_INFO_T *cipher_t, META_DATA_INFO_T *text_t, RSA_KEY_INFO_T *key_t);
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
/*
 * output: key
 */
int CRYPTO_AES_key_generate(AES_KEY_HANDLE_T *key_handle_t);

/*
 * input : key, key_len
 * output: key_handle_t
 */
int CRYPTO_AES_init(AES_KEY_HANDLE_T *key_handle_t);

/*
 * input : key_handle_t
 */
int CRYPTO_AES_release(AES_KEY_HANDLE_T *key_handle_t);

/*
 * input : text_t, key
 * output: cipher_t
 */
int CRYPTO_AES_encrypt(const META_DATA_INFO_T *text_t, META_DATA_INFO_T *cipher_t, AES_KEY_HANDLE_T *key_handle_t);

/*
 * input : cipher_t, key
 * output: text_t
 */
int CRYPTO_AES_decrypt(const META_DATA_INFO_T *cipher_t, META_DATA_INFO_T *text_t, AES_KEY_HANDLE_T *key_handle_t);
////////////////////////////////////////////////////////////////////////////////////

#ifdef  __cplusplus
}
#endif

#endif /* _CRYPTO_MODULE_H_ */
