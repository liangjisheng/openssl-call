
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_sha384(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpszMD = (unsigned char *)malloc(SHA384_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA384_DIGEST_LENGTH);

	SHA512_CTX ctx;
	SHA384_Init(&ctx);
	SHA384_Update(&ctx, lpszInput, nLen);
	SHA384_Final(lpszMD, &ctx);

	printf("sha384: ");
	disp(lpszMD, SHA384_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

int test_sha384_1(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpucszInput = (unsigned char *)malloc(nLen + 1);
	memset(lpucszInput, 0, nLen + 1);
	memcpy(lpucszInput, lpszInput, nLen);

	unsigned char *lpszMD = (unsigned char *)malloc(SHA384_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA384_DIGEST_LENGTH);
	unsigned char *lpszRet = NULL;

	lpszRet = SHA384(lpucszInput, nLen, lpszMD);
	printf("sha384: ");
	disp(lpszMD, SHA384_DIGEST_LENGTH);
	printf("sha384: ");
	disp(lpszRet, SHA384_DIGEST_LENGTH);

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

