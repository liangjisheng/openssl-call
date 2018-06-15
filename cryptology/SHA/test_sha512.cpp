
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_sha512(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpszMD = (unsigned char *)malloc(SHA512_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA512_DIGEST_LENGTH);

	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, lpszInput, nLen);
	SHA512_Final(lpszMD, &ctx);

	printf("sha512: ");
	disp(lpszMD, SHA512_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

int test_sha512_1(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpucszInput = (unsigned char *)malloc(nLen + 1);
	memset(lpucszInput, 0, nLen + 1);
	memcpy(lpucszInput, lpszInput, nLen);

	unsigned char *lpszMD = (unsigned char *)malloc(SHA512_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA512_DIGEST_LENGTH);
	unsigned char *lpszRet = NULL;

	lpszRet = SHA512(lpucszInput, nLen, lpszMD);
	printf("sha512: ");
	disp(lpszMD, SHA512_DIGEST_LENGTH);
	printf("sha512: ");
	disp(lpszRet, SHA512_DIGEST_LENGTH);

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

