
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef _DEBUG
#include <vld.h>
#endif

void bn_printf(BIGNUM *a, int n)
{
	printf("0x");
	FILE* f = fopen("BigNum.txt", "w");
	BN_print_fp(f, a);
	fclose(f);
	// BN_print_fp(stdout, a);
	if (n)
		printf("\n");
}

void bn_hex_printf(BIGNUM * a)  
{  
	char *p = BN_bn2hex(a);  
	printf("0x%s\n", p);  
	OPENSSL_free(p);  
}

void bn_dec_printf(BIGNUM * a)  
{  
	char *p = BN_bn2dec(a);  
	printf("%s\n", p);  
	OPENSSL_free(p);  
}


void test_bignum1();
void test_bignum2();

int main()
{
	test_bignum1();
	test_bignum2();

	getchar();
	return 0;
}

