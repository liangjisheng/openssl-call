
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_sha224(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpszMD = (unsigned char *)malloc(SHA224_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA224_DIGEST_LENGTH);

	SHA256_CTX ctx;
	SHA224_Init(&ctx);
	SHA224_Update(&ctx, lpszInput, nLen);
	SHA224_Final(lpszMD, &ctx);

	printf("sha224: ");
	disp(lpszMD, SHA224_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

int test_sha224_1(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpucszInput = (unsigned char *)malloc(nLen + 1);
	memset(lpucszInput, 0, nLen + 1);
	memcpy(lpucszInput, lpszInput, nLen);

	unsigned char *lpszMD = (unsigned char *)malloc(SHA224_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA224_DIGEST_LENGTH);
	unsigned char *lpszRet = NULL;

	lpszRet = SHA224(lpucszInput, nLen, lpszMD);
	printf("sha224: ");
	disp(lpszMD, SHA224_DIGEST_LENGTH);
	printf("sha224: ");
	disp(lpszRet, SHA224_DIGEST_LENGTH);

	if (lpucszInput)
	{
		free(lpucszInput);
		lpucszInput = NULL;
	}

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

