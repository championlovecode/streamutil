#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>
#include <pjmedia/transport_srtp.h>
#include <stdlib.h>	/* atoi() */
#include <stdio.h>

#include <malloc.h>
#include "crypto_module.h"

#ifdef _WIN32
extern "C"{
#include "openssl/applink.c"
};
#endif



AES_KEY_HANDLE_T key_handle_t = {0};
void printfkey(char* temp,int len);

#if 0
void printfkey(char* temp,int len)
{
	printf("\n");
	int i =0;
	for(i=0;i < len; i++)
	{
		printf("%2x ",temp[i]&0xff);	
	}
	printf("\n");

}
#endif 

void CRYPTO_AES_encrypt_rtp(META_DATA_INFO_T *text_t, META_DATA_INFO_T *cipher_t)
{
	printf("\n CRYPTO_AES_encrypt_test come in \n");

	printf("key_handle_t.len = %d",key_handle_t.key_len);
	printfkey(key_handle_t.key,key_handle_t.key_len);

	if (CRYPTO_AES_encrypt(text_t,cipher_t, &key_handle_t))
	{
		printf("CRYPTO_AES_encrypt Error\n");		 
	}

	printf("\n CRYPTO_AES_encrypt_test come out \n");	
}

 void CRYPTO_AES_decrypt_rtp(META_DATA_INFO_T *cipher_t, META_DATA_INFO_T *text_t)
 {
	 printf("\n CRYPTO_AES_decrypt_rtp come in \n");

	 printf("cipher_t.len = %d",cipher_t->len);
	 printfkey(cipher_t->addr,cipher_t->len);
 
	 if (CRYPTO_AES_decrypt(cipher_t,text_t, &key_handle_t))
	 {
		 printf("CRYPTO_AES_encrypt Error\n");		  
	 }

	 printf("\n CRYPTO_AES_decrypt_rtp come out \n");
	 
 }


void CRYPTO_AES_encrypt_init(void)
{	 
	CRYPTO_AES_encrypt_decrypt_register((PTR_ENCRYPT)CRYPTO_AES_encrypt_rtp,(PTR_ENCRYPT)CRYPTO_AES_decrypt_rtp); 	

	// AES128 key 
	key_handle_t.key_len = 16;
	unsigned char  key_temp[16]={0x8d,0x2f,0x35,0x80,0x11,0xca,0x81,0x7a,0xc3,0x1,0xe6,0x69,0xa3,0xc7,0x4c,0x18}; 
	memcpy(key_handle_t.key,key_temp,key_handle_t.key_len);
	
	if (CRYPTO_AES_init(&key_handle_t))
	{
		printf("CRYPTO_AES_init ERROR \n");
	}
	printf("\n CRYPTO_AES_encrypt_init OK  \n");
	
}



