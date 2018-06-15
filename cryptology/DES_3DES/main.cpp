
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int test_DES_CBC();
void test_DES_ECB();
void test_DES_ECB_1();

int main()
{
	//test_DES_CBC();
	//test_DES_ECB();
	test_DES_ECB_1();

	getchar();
	return 0;
}
