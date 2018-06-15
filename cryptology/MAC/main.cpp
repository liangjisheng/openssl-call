
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "func.h"

#ifdef _DEBUG
    #include <vld.h>
#endif

void disp(const char *data, const int nLen)
{
	int i = 0;
	for (i = 0; i < nLen; ++i)
		printf("%02x", data[i]);
	printf("\n");
}

void disp(const unsigned char *data, const int nLen)
{
	int i = 0;
	for (i = 0; i < nLen; ++i)
		printf("%02x", data[i]);
	printf("\n");
}

int test_hmac();
int test_cmac();

int main()
{
	//test_hmac();
	test_cmac();

	//unsigned char szHexs[32] = {0};
	//char *szData = "01234000056789abcdef";
	//int nLen = strlen(szData);
	//memcpy(szHexs, szData, nLen);
	//unsigned char szBytes[16] = {0};
	//MyHEX_BYTES(szHexs, nLen, szBytes);
	//disp(szBytes, nLen / 2);

	//memset(szHexs, 0, 32);
	//MyBYTES_HEX(szBytes, nLen / 2, szHexs);
	//printf("%s\n", szHexs);
	//string strHexs = (char *)(&szHexs[0]);

	//unsigned char ucsz1[10] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5 };
	//unsigned char ucsz2[10] = {0};
	//char *p = "012345";
	//int nLen = strlen(p);
	//memcpy(ucsz2, p, nLen);

	//if (0 == memcpy(ucsz1, ucsz2, nLen))
	//	printf("ucsz1 == ucsz2\n");
	//else
	//	printf("ucsz1 != ucsz2\n");

	getchar();
	return 0;
}

