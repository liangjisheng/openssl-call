
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
	// ������ת��Ϊʮ�������ַ���������ֵΪ���ɵ�ʮ�������ַ������ⲿ��Ҫ��OPENSSL_free�����ͷ�
	char *p = BN_bn2hex(a);  
	printf("0x%s\n", p);  
	OPENSSL_free(p);  
}

void bn_dec_printf(const BIGNUM * a)  
{  
	// char *BN_bn2dec(const BIGNUM *a)
	// ������ת���������ַ���������ֵ�д�������ַ����������ڲ�����ռ�
	// �û��������ⲿ��OPENSSL_free�����ͷŸÿռ�
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

