
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openssl\rsa.h"

void printHex(const char *psz, const int nLen)
{
	char tmp[3] = {0};
	int i = 0;
	for (i = 0; i < nLen; ++i)
	{
		sprintf_s(tmp, "%02x", psz[i]);
		printf("%s", tmp);
	}
	printf("\n");
}

void test_RSA_1()
{
	BIGNUM b = {0};
	// pRsa中包含N,D，可以修改
	RSA *pRsa = RSA_generate_key(1024, RSA_F4, 0, 0);

	char sz[] = "abcdefg";
	printf("source data: %s\n", sz);
	printHex(sz, strlen(sz));
	int len = RSA_size(pRsa);

	unsigned char *p = new unsigned char[len + 1];
	memset(p, 0, len + 1);
	RSA_public_encrypt(sizeof(sz), (unsigned char *)sz, p, pRsa, RSA_PKCS1_PADDING);
	printf("encrypt result: %s\n", p);

	for (int i = 0; i < len; ++i)
	{
		char tmp[3] = {0};
		sprintf_s(tmp, "%02x", p[i]);
		printf("%s", tmp);
	}
	printf("\n");
	//printHex((char *)p, len);

	char out[1024] = {0};
	RSA_private_decrypt(len, p, (unsigned char *)out, pRsa, RSA_PKCS1_PADDING);
	printf("decrypt result: %s\n", out);
	printHex(out, strlen(out));

	RSA_free(pRsa);
	delete [] p;
}

