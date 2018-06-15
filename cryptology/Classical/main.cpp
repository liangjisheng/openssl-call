
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

void test_trans();
void test_stream();


int main()
{
	//test_trans();
	test_stream();

	getchar();
	return 0;
}

