
#include <stdio.h>
#include <string.h>

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

int test_md2();
int test_md(char *lpszName);
int test_md_1(const char *lpszInput);
int test_algo_hash(const char *algo);
int test_md4(const char *lpszInput);
int test_md5(const char *lpszInput);
int test_mdc2(const unsigned char *lpszInput, size_t len);

int main()
{
	//test_md2();

	//test_md("md4");
	//test_md("md5");
	//test_md("sha");
	//test_md("sha1");
	//test_md("sha224");
	//test_md("sha256");
	//test_md("sha384");
	//test_md("sha512");
	//printf("\n\n");

	//test_algo_hash("md4");
	//printf("\n");
	//test_algo_hash("md5");
	//printf("\n");
	//test_algo_hash("sha1");
	//printf("\n");
	//test_algo_hash("sha224");
	//printf("\n");
	//test_algo_hash("sha256");
	//printf("\n");
	//test_algo_hash("sha384");
	//printf("\n");
	//test_algo_hash("sha512");
	//printf("\n");

	//test_md4("Test Message");
	//test_md5("Test Message");

	//char *lpszInput = "Test Message";
	//unsigned char szInput[64] = {0};
	//memcpy(szInput, lpszInput, strlen(lpszInput));
	//test_mdc2(szInput, strlen(lpszInput));

	//test_md_1(lpszInput);

	getchar();
	return 0;
}

