
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/mdc2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_md_1(const char *lpszInput)
{
	int nLen = strlen(lpszInput);
	unsigned char *lpucszInput = (unsigned char*)malloc(nLen);
	memcpy(lpucszInput, lpszInput, nLen);

	// 返回值和第三个参数所用内存其实是同一块，这两个释放了一个就不会有内存泄露了
	// 必须给第三个参数分配内存
	unsigned char *lpszRes = NULL;
	//(unsigned char *)malloc(MDC2_DIGEST_LENGTH);
	//memset(lpszRes, 0, MDC2_DIGEST_LENGTH);
	unsigned char *lpszMD = (unsigned char *)malloc(MDC2_DIGEST_LENGTH + 1);
	memset(lpszMD, 0, MDC2_DIGEST_LENGTH + 1);

	lpszRes = MDC2(lpucszInput, nLen, lpszMD);
	printf("mdc2: ");
	disp(lpszMD, MDC2_DIGEST_LENGTH);
	printf("mdc2: ");
	disp(lpszRes, MDC2_DIGEST_LENGTH);

	memset(lpszMD, 0, MDC2_DIGEST_LENGTH + 1);
	lpszRes = MD4(lpucszInput, nLen, lpszMD);
	printf("md4: ");
	disp(lpszMD, MDC2_DIGEST_LENGTH);
	printf("md4: ");
	disp(lpszMD, MDC2_DIGEST_LENGTH);

	memset(lpszMD, 0, MDC2_DIGEST_LENGTH + 1);
	lpszRes = MD5(lpucszInput, nLen, lpszMD);
	printf("md5: ");
	disp(lpszMD, MDC2_DIGEST_LENGTH);
	printf("md5: ");
	disp(lpszMD, MDC2_DIGEST_LENGTH);
	printf("\n");

	if (lpucszInput)
	{
		free(lpucszInput);
		lpucszInput = NULL;
	}

	//if (lpszRes)
	//{
	//	free(lpszRes);
	//	lpszRes = NULL;
	//}

	if (lpszMD)
	{
		free(lpszMD);
		lpszMD = NULL;
	}

	return 0;
}

