
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/md5.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_md5(const char *lpszInput)
{
	MD5_CTX ctx;
	unsigned char *lpszMD = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
	memset(lpszMD, 0, MD5_DIGEST_LENGTH);

	MD5_Init(&ctx);
	MD5_Update(&ctx, lpszInput, strlen(lpszInput));
	MD5_Final(lpszMD, &ctx);

	printf("md5: ");
	disp(lpszMD, MD5_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

