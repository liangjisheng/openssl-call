
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>

#include "func.h"

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_sha256(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpszMD = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA256_DIGEST_LENGTH);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, lpszInput, nLen);
	SHA256_Final(lpszMD, &ctx);

	printf("sha256: ");
	disp(lpszMD, SHA256_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

int test_sha256(const string &strHexs)
{
	string strBytes;
	MyHEX_BYTES(strHexs, strHexs.size(), strBytes);
	int nLen = strBytes.size();
	unsigned char *lpszMD = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA256_DIGEST_LENGTH);

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, strBytes.c_str(), nLen);
	SHA256_Final(lpszMD, &ctx);

	printf("sha256: ");
	disp(lpszMD, SHA256_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

int test_sha256_1(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpucszInput = (unsigned char *)malloc(nLen + 1);
	memset(lpucszInput, 0, nLen + 1);
	memcpy(lpucszInput, lpszInput, nLen);

	unsigned char *lpszMD = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
	memset(lpszMD, 0, SHA256_DIGEST_LENGTH);
	unsigned char *lpszRet = NULL;

	lpszRet = SHA256(lpucszInput, nLen, lpszMD);
	printf("sha256: ");
	disp(lpszMD, SHA256_DIGEST_LENGTH);
	printf("sha256: ");
	disp(lpszRet, SHA256_DIGEST_LENGTH);

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

