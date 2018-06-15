
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdio.h>

void bn_hex_printf(BIGNUM * a);
void bn_dec_printf(BIGNUM * a);

static void test_print()
{
	BIGNUM *bn = NULL;
	BIO *b = NULL;
	char a[20] = {0};
	int ret = 0;

	bn = BN_new();
	strcpy(a, "32");
	printf("a = %s\n", a);
	ret = BN_hex2bn(&bn, a);
	printf("hex: ");
	bn_hex_printf(bn);
	printf("dec: ");
	bn_dec_printf(bn);
	//b = BIO_new(BIO_s_file());
	//ret = BIO_set_fp(b, stdout, BIO_NOCLOSE);
	//BIO_write(b, "aaa", 3);
	//BN_print(b, bn);

	BN_free(bn);
	//BIO_free(b);
}

static void test_add()
{
	BIGNUM *a, *b, *add;
	BIO *out;
	char c[20], d[20];
	int ret;

	a = BN_new();
	strcpy(c, "32");
	printf("c = %s\n", c);
	ret = BN_hex2bn(&a, c);
	printf("dec: ");
	bn_dec_printf(a);
	printf("hex: ");
	bn_hex_printf(a);

	b = BN_new();
	strcpy(d, "100");
	printf("d = %s\n", d);
	ret = BN_hex2bn(&b, d);
	printf("dec: ");
	bn_dec_printf(b);
	printf("hex: ");
	bn_hex_printf(b);

	//out = BIO_new_fp(stdout, BIO_NOCLOSE);
	//BIO_printf(out, "hello world\n");
	//ret = BIO_set_fp(out, stdout, BIO_NOCLOSE);

	add = BN_new();
	ret = BN_add(add, a, b);
	if (1 != ret)
	{
		printf("err.\n");
		return ;
	}
	printf("bn 0x32 + 0x100 = 0x");
	bn_hex_printf(add);

	//BIO_puts(out, "bn 0x32 + 0x100 = 0x");
	//BN_print(out, add);
	//BIO_puts(out, "\n");

	BN_free(a);
	BN_free(b);
	BN_free(add);
	//BIO_free(out);
}

static void test_sub()
{
	BIGNUM *a, *b, *sub;
	//BIO *out;
	char c[20] = {0}, d[20] = {0};
	int ret = 0;

	a = BN_new();
	strcpy(c, "100");
	ret = BN_hex2bn(&a, c);
	b = BN_new();
	strcpy(d, "32");
	ret = BN_hex2bn(&b, d);

	printf("dec a: ");
	bn_dec_printf(a);
	printf("hex a: ");
	bn_hex_printf(a);
	printf("dec b: ");
	bn_dec_printf(b);
	printf("hex b: ");
	bn_hex_printf(b);

	//out = BIO_new(BIO_s_file());
	//FILE *fp = fopen("res.txt", "w");
	//ret = BIO_set_fp(out, fp, BIO_NOCLOSE);

	sub = BN_new();
	ret = BN_sub(sub, a, b);
	if (1 != ret)
	{
		printf("err\n");
		return ;
	}
	printf("dec sub: ");
	bn_dec_printf(sub);
	printf("hex sub: ");
	bn_hex_printf(sub);


	//BIO_puts(out, "bn 0x100 - 0x32 = 0x");
	//BN_print(out, sub);
	//BIO_puts(out, "\n");

	BN_free(a);
	BN_free(b);
	BN_free(sub);

	//BIO_free(out);
}

static void test_mul_div()
{
	BIGNUM *a, *b, *mul;
	BN_CTX *ctx;
	char c[20] = {0}, d[20] = {0};
	int ret = 0;

	ctx = BN_CTX_new();
	a = BN_new();
	strcpy(c, "32");
	ret = BN_hex2bn(&a, c);

	b = BN_new();
	strcpy(d, "100");
	ret = BN_hex2bn(&b, d);

	printf("dec a: ");
	bn_dec_printf(a);
	printf("hex a: ");
	bn_hex_printf(a);
	printf("dec b: ");
	bn_dec_printf(b);
	printf("hex b: ");
	bn_hex_printf(b);

	mul = BN_new();
	ret = BN_mul(mul, a, b, ctx);

	if (1 != ret)
	{
		printf("err\n");
		return ;
	}

	printf("dec mul: ");
	bn_dec_printf(mul);
	printf("hex mul: ");
	bn_hex_printf(mul);
	printf("\n");


	memset(c, 0, 20);
	memset(d, 0, 20);
	strcpy(c, "100");
	ret = BN_hex2bn(&a, c);
	strcpy(d, "17");
	ret = BN_hex2bn(&b, d);

	printf("dec a: ");
	bn_dec_printf(a);
	printf("hex a: ");
	bn_hex_printf(a);
	printf("dec b: ");
	bn_dec_printf(b);
	printf("hex b: ");
	bn_hex_printf(b);

	BIGNUM *div, *rem;
	div = BN_new();
	rem = BN_new();
	ret = BN_div(div, rem, a, b, ctx);

	if (1 != ret)
	{
		printf("err\n");
		return ;
	}

	printf("dec div: ");
	bn_dec_printf(div);
	printf("hex div: ");
	bn_hex_printf(div);
	printf("dec rem: ");
	bn_dec_printf(rem);
	printf("hex rem: ");
	bn_hex_printf(rem);

	BN_free(a);
	BN_free(b);
	BN_free(mul);

	BN_free(div);
	BN_free(rem);
}

static void test_square()
{
	BIGNUM *a, *sqr;
	BN_CTX *ctx;
	ctx = BN_CTX_new();
	char c[20] = {0};
	int ret = 0;

	a = BN_new();
	strcpy(c, "100");
	ret = BN_hex2bn(&a, c);
	sqr = BN_new();

	ret = BN_sqr(sqr, a, ctx);
	if (1 != ret)
	{
		printf("err\n");
		return ;
	}

	printf("dec a: ");
	bn_dec_printf(a);
	printf("hex a: ");
	bn_hex_printf(a);
	printf("dec sqr: ");
	bn_dec_printf(sqr);
	printf("hex sqr: ");
	bn_hex_printf(sqr);

	BN_free(a);
	BN_free(sqr);
	BN_CTX_free(ctx);
}

static void test_exp()
{
	BIGNUM *a, *exp, *b;
	BN_CTX *ctx;
	char c[20] = {0}, d[20] = {0};
	int ret = 0;

	ctx = BN_CTX_new();
	if (NULL == ctx)
		return ;

	a = BN_new();
	strcpy(c, "100");
	ret = BN_hex2bn(&a, c);
	b = BN_new();
	strcpy(d, "3");
	ret = BN_hex2bn(&b, d);

	exp = BN_new();
	// ¼ÆËãaµÄb´ÎÃÝ
	ret = BN_exp(exp, a, b, ctx);

	if (1 != ret)
	{
		printf("err\n");
		return ;
	}

	printf("dec a: ");
	bn_dec_printf(a);
	printf("hex a: ");
	bn_hex_printf(a);

	printf("dec b: ");
	bn_dec_printf(b);
	printf("hex b: ");
	bn_hex_printf(b);

	printf("dec exp: ");
	bn_dec_printf(exp);
	printf("hex exp: ");
	bn_hex_printf(exp);

	BN_free(a);
	BN_free(b);
	BN_free(exp);

	BN_CTX_free(ctx);
}

void test_bignum2()
{
	// test_add();

	//int nRet = 0;
	//BIGNUM *bn1;
	//bn1 = BN_new();
	//nRet = BN_rand(bn1, 1, 0, 1);
	//printf("dec bn1: ")
	//bn_dec_printf(bn1);
	//printf("hex bn1: ");
	//bn_hex_printf(bn1);

	// test_sub();

	// test_mul_div();

	// test_square();

	test_exp();
}

