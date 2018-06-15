
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define BREAK_ERROR(msg){\
	fprintf(stderr, "error break [%s]\n", msg);\
	break;\
}

#define CIPHER_INFO(e){\
	fprintf(stderr, "key_len:[%d]", EVP_CIPHER_CTX_key_length(e));\
	fprintf(stderr, "iv_len:[%d]", EVP_CIPHER_CTX_iv_length(e));\
	fprintf(stderr, "mode:[%d]", EVP_CIPHER_CTX_mode(e));\
	fprintf(stderr, "flag:[%d]", EVP_CIPHER_CTX_flags(e));\
}

int test_ecb_aes(unsigned char *buf1, unsigned char *buf2, unsigned char *buf3, 
	int *len1, int *len2, int *len3, unsigned char *key)
{
	int ret = 0, tmplen = 0;
	*len2 = *len3 = 0;

	// encrypt
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	CIPHER_INFO(&ctx);

	do {
		if (!EVP_EncryptUpdate(&ctx, (unsigned char *)buf2, len2, (unsigned char *)buf1, *len1))
			BREAK_ERROR("encryptupdate");
		if (!EVP_EncryptFinal_ex(&ctx, (unsigned char *)(buf2 + (*len2)), &tmplen))
			BREAK_ERROR("encryptfinal");
	}while (0);

	*len2 = *len2 + tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	fprintf(stderr, "encrypt:len1:[%d] len2:[%d]\n", *len1, *len2);

	// decrypt
	EVP_CIPHER_CTX ctx_d;
	EVP_CIPHER_CTX_init(&ctx_d);
	EVP_EncryptInit_ex(&ctx_d, EVP_aes_128_ecb(), NULL, key, NULL);

	do {
		if (!EVP_DecryptUpdate(&ctx_d, (unsigned char *)buf3, len3, (unsigned char *)buf2, *len2))
			BREAK_ERROR("decryptupdate");
		if (!EVP_EncryptFinal_ex(&ctx_d, (unsigned char *)(buf3 + (*len3)), &tmplen))
			BREAK_ERROR("decryptfinal");
		//if (!EVP_DecryptFinal(&ctx_d, (unsigned char *)(buf3 + (*len3)), &tmplen))
		//	BREAK_ERROR("decryptfinal");
	}while(0);

	*len3 = *len3 + tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx_d);
	fprintf(stderr, "encrypt:len2:[%d] len3[%d]\n", *len2, *len3);

	// compare the data
	if (memcmp(buf1, buf3, *len1) == 0)
		fprintf(stderr, "%s success \n", __FUNCTION__);
	else
		fprintf(stderr, "%s failed\n", __FUNCTION__);

	return 0;
}


#define BUF_SIZE 102402

int main()
{
	int i, len1, len2, len3;
	unsigned char key_8[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	unsigned char *buf1 = (unsigned char *)malloc(BUF_SIZE + 1);
	//memset(buf1, 0, BUF_SIZE + 1);
	unsigned char *buf2 = (unsigned char *)malloc(BUF_SIZE + 128);
	//memset(buf2, 0, BUF_SIZE + 128);
	unsigned char *buf3 = (unsigned char *)malloc(BUF_SIZE + 128);
	//memset(buf3, 0, BUF_SIZE + 128);
	len1 = len2 = len3 = BUF_SIZE;

	for (i = 0; i < BUF_SIZE; ++i)
		buf1[i] = i % 256;

	test_ecb_aes(buf1, buf2, buf3, &len1, &len2, &len3, key_8);

	if (NULL != buf1)
	{
		free(buf1);
		buf1 = NULL;
	}

	if (NULL != buf2)
	{
		free(buf2);
		buf2 = NULL;
	}

	if (NULL != buf3)
	{
		free(buf3);
		buf3 = NULL;
	}

	getchar();
	return 0;
}

