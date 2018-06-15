
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/mdc2.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_mdc2(const unsigned char *lpszInput, size_t len)
{
	MDC2_CTX ctx;
	unsigned char *lpszMD = (unsigned char *)malloc(MDC2_DIGEST_LENGTH);
	memset(lpszMD, 0, MDC2_DIGEST_LENGTH);

	MDC2_Init(&ctx);
	MDC2_Update(&ctx, lpszInput, len);
	MDC2_Final(lpszMD, &ctx);

	printf("mdc2: ");
	disp(lpszMD, MDC2_DIGEST_LENGTH);

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

