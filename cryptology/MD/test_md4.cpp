
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md4.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_md4(const char *lpszInput)
{
	MD4_CTX ctx;
	//char *lpszInput = "Test Message";
	unsigned char *lpszMD = (unsigned char *)malloc(MD4_DIGEST_LENGTH);
	memset(lpszMD, 0, MD4_DIGEST_LENGTH);

	MD4_Init(&ctx);
	MD4_Update(&ctx, lpszInput, strlen(lpszInput));
	MD4_Final(lpszMD, &ctx);

	printf("md4: ");
	disp(lpszMD, MD4_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = 0;
	}

	return 0;
}