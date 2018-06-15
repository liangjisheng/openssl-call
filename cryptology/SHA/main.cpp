
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

int test_sha(const char *lpszInput);
int test_sha_1(const char *lpszInput);
int test_sha1(const char *lpszInput);
int test_sha1_1(const char *lpszInput);
int test_sha224(const char *lpszInput);
int test_sha224_1(const char *lpszInput);
int test_sha256(const char *lpszInput);
int test_sha256(const string &strHexs);
int test_sha256_1(const char *lpszInput);
int test_sha384(const char *lpszInput);
int test_sha384_1(const char *lpszInput);
int test_sha512(const char *lpszInput);
int test_sha512_1(const char *lpszInput);

int main()
{
	//test_sha("Test Message");
	//test_sha_1("Test Message");

	//test_sha1("Test Message");
	//test_sha1_1("Test Message");

	//test_sha224("Test Message");
	//test_sha224_1("Test Message");

	string strHexs("833ac588784b6409673fae00cce276f215578d8a00000003");
	test_sha256(strHexs);
	//test_sha256_1("Test Message");

	//test_sha384("Test Message");
	//test_sha384_1("Test Message");

	test_sha512("Test Message");
	test_sha512_1("Test Message");

	getchar();
	return 0;
}

