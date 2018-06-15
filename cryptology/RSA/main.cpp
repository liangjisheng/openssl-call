
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

void test_RSA();
void test_RSA_1();
void test_RSA_2();


int main()
{
	//test_RSA();
	//test_RSA_1();
	//test_RSA_2();

	getchar();
	return 0;
}

