
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_sha1(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpszMD = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA_DIGEST_LENGTH);

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, lpszInput, nLen);
	SHA1_Final(lpszMD, &ctx);

	printf("sha1: ");
	disp(lpszMD, SHA_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

int test_sha1_1(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpucszInput = (unsigned char *)malloc(nLen + 1);
	memset(lpucszInput, 0, nLen + 1);
	memcpy(lpucszInput, lpszInput, nLen);

	unsigned char *lpszMD = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA_DIGEST_LENGTH);
	unsigned char *lpszRet = NULL;

	lpszRet = SHA1(lpucszInput, nLen, lpszMD);
	printf("sha1: ");
	disp(lpszMD, SHA_DIGEST_LENGTH);
	printf("sha1: ");
	disp(lpszRet, SHA_DIGEST_LENGTH);

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

