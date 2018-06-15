
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include "openssl/dh.h"

void bn_hex_printf(BIGNUM * a);
void bn_dec_printf(BIGNUM * a);
void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);
void print_sharedKey(unsigned char *lpszKey, int nLen);


int test_DH()
{
	DH *d1 = NULL, *d2 = NULL;
	int ret = 0, size = 0, i = 0, len1 = 0, len2 = 0;
	unsigned char sharekey1[128] = {0}, sharekey2[128] = {0};

	d1 = DH_new();
	d2 = DH_new();

	// 共享密钥的位长64,128,192,256,512,1024,2048
	// 密钥越长，在生成密钥参数时所需要的时间越多(DH_generate_parameters_ex)
	int nKeyLenBits = 256;

	// 生成d1的密钥参数(p,g)
	ret = DH_generate_parameters_ex(d1, nKeyLenBits, DH_GENERATOR_2, NULL);
	if (ret != 1)
	{
		printf("DH_generate_parameters_ex err\n");
		return -1;
	}
	else
	{
		// 打印p,g
		printf("p is: ");
		bn_hex_printf(d1->p);
		printf("g is: ");
		bn_hex_printf(d1->g);
		printf("DH_generate_parameters_ex ok\n\n");
	}

	// 检查密钥参数
	ret = DH_check(d1, &i);
	if (ret != 1)
	{
		printf("DH_check err\n");
		if (i & DH_CHECK_P_NOT_PRIME)
			printf("p value is not prime\n");
		if (i & DH_CHECK_P_NOT_SAFE_PRIME)
			printf("p value is not a safe prime\n");
		if (i & DH_UNABLE_TO_CHECK_GENERATOR)
			printf("unable to check the generator value\n");
		if (i & DH_NOT_SUITABLE_GENERATOR)
			printf("the g value si not a generator\n");
	}
	else
		printf("DH parameter appear to be ok\n");

	size = DH_size(d1);		// 密钥大小(字节长度)
	printf("DH key1 size: %d\n\n", size);

	// 生成公私钥
	ret = DH_generate_key(d1);
	if (ret != 1)
	{
		printf("DH_generate_key err");
		return -1;
	}

	printf("d1 private key: ");
	bn_hex_printf(d1->priv_key);
	printf("d1 public key: ");
	bn_hex_printf(d1->pub_key);
	printf("\n");

	// p和g为公开的密钥参数,因此可以拷贝
	d2->p = BN_dup(d1->p);
	d2->g = BN_dup(d1->g);

	// 生成公私钥，用于测试生成共享密钥
	ret = DH_generate_key(d2);
	if (ret != 1)
	{
		printf("DH_generate_key err\n");
		return -1;
	}

	printf("d2 private key: ");
	bn_hex_printf(d2->priv_key);
	printf("d2 public key: ");
	bn_hex_printf(d2->pub_key);
	printf("\n");

	// 检查公钥
	ret = DH_check_pub_key(d1, d1->pub_key, &i);
	if (ret != 1)
	{
		if (i & DH_CHECK_PUBKEY_TOO_SMALL)
			printf("pub key too small\n");
		if (i & DH_CHECK_PUBKEY_TOO_LARGE)
			printf("pub key too large\n");
	}

	// 计算共享密钥
	len1 = DH_compute_key(sharekey1, d2->pub_key, d1);
	len2 = DH_compute_key(sharekey2, d1->pub_key, d2);
	if (len1 != len2)
	{
		printf("生成共享密钥失败1\n");
		return -1;
	}

	if (memcmp(sharekey1, sharekey2, len1) != 0)
	{
		printf("生成共享密钥失败2\n");
		return -1;
	}
	else
		printf("生成共享密钥成功\n");

	printf("\n");
	print_sharedKey(sharekey1, len1);
	print_sharedKey(sharekey2, len2);

	//BIO *b = BIO_new(BIO_s_file());
	//BIO_set_fp(b, stdout, BIO_NOCLOSE);
	//DHparams_print(b, d1);
	//BIO_free(b);

	DH_free(d1);
	DH_free(d2);

	return 0;
}

void print_sharedKey(unsigned char *lpszKey, int nLen)
{
	int i = 0;
	printf("dec: ");
	for (i = 0; i < nLen; ++i)
		printf("%d ", lpszKey[i]);
	printf("\n");

	printf("hex: ");
	for (i = 0; i < nLen; ++i)
	{
		char tmp[3] = {0};
		sprintf_s(tmp, 3, "%02x", lpszKey[i]);
		printf("%s ", tmp);
	}
	printf("\n");
}
