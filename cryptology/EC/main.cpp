
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#include "func.h"

#ifdef _DEBUG
    #include <vld.h>
#endif

void handleErrors() { printf("Error occurred.\n"); }

void bn_hex_printf(const BIGNUM * a)  
{  
	// char *BN_bn2hex(const BIGNUM *a)
	// 将大数转换为十六进制字符串。返回值为生成的十六进制字符串，外部需要用OPENSSL_free函数释放
	char *p = BN_bn2hex(a);  
	printf("0x%s\n", p);  
	OPENSSL_free(p);  
}

void bn_dec_printf(const BIGNUM * a)  
{  
	// char *BN_bn2dec(const BIGNUM *a)
	// 将大数转换成整数字符串。返回值中存放整数字符串，它由内部分配空间
	// 用户必须在外部用OPENSSL_free函数释放该空间
	char *p = BN_bn2dec(a);  
	printf("%s\n", p);  
	OPENSSL_free(p);  
}

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

void disp(const char *str, const void *pbuf, const int size)
{
	int i = 0;
	if (str != NULL)
		printf("%s:\n", str);
	if (pbuf != NULL && size > 0)
	{
		for (i = 0; i < size; ++i)
			printf("%02x ", *((unsigned char *)pbuf + i));
		putchar('\n');
	}
	putchar('\n');
}


void test();
void test_builtin_curves();
int test_ecc();

int main()
{
	//test();
	test_builtin_curves();
	
	getchar();
	return 0;
}

