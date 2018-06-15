
// OpenSSL实现的ECC算法，包括三部分:ECC算法(crypto/ec),椭圆曲线数字签名算法ECDSA(crypto/ecdsa)
// 椭圆曲线密钥交换算法ECDH(crypto/dh)

// 椭圆曲线密钥生成时，首先用户需要选取一种椭圆曲线，openssl内置了67中，调用EC_get_builtin_curves
// 获取该列表，然后根据选择的椭圆曲线计算密钥生成参数group,最后根据密钥生成参数来计算公私钥

// 获取椭圆曲线列表
// size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)
// 根据指定的椭圆曲线来生成密钥参数
// EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
// 根据密钥参数生成ECC公私钥
// int EC_KEY_generate_key(EC_KEY *eckey)
// 检查ECC密钥
// int EC_KEY_check_key(const EC_KEY *eckey)
// 获取 ECC 密钥大小字节数
// int ECDSA_size(const EC_KEY *r)

// 签名，返回1表示成功
// int ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char
					// *sig, unsigned int *siglen, EC_KEY *eckey)
// ECDSA_sign_ex

// 验证，返回1表示合法
// int ECDSA_verify(int type, const unsigned char *dgst, int dgst_len,
			// const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)

// 获取公钥
// EC_KEY_get0_public_key
// 获取私钥
// EC_KEY_get0_private_key

// 生成共享密钥
//int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
	//const EC_KEY *eckey,
	//void *(*KDF) (const void *in, size_t inlen, void *out,
	//size_t *outlen))

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>

int test_ecc()
{
	EC_KEY *key1, *key2;
	const EC_POINT *pubkey1, *pubkey2;
	EC_GROUP *group1, *group2;
	unsigned int ret, nid, size, i, sig_len;
	unsigned char *signature, digest[20] = {0};
	BIO *berr;
	EC_builtin_curve *curves;
	int crv_len = 0;
	char sharKey1[128] = {0};
	char sharKey2[128] = {0};
	int len1 = 0, len2 = 0;

	// 构造EC_KEY数据结构
	key1 = EC_KEY_new();
	if (NULL == key1)
	{
		printf("EC_KEY_new err\n");
		return -1;
	}
	key2 = EC_KEY_new();
	if (NULL == key2)
	{
		printf("EC_KEY_new err\n");
		return -1;
	}

	// 获取内置椭圆曲线个数
	crv_len = EC_get_builtin_curves(NULL, 0);	// 67
	curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
	// 获取内置椭圆曲线列表
	EC_get_builtin_curves(curves, crv_len);

	// nid = curvers[0].nid;	// 会有错，原因是密钥太短
	// 选取一种椭圆曲线
	nid = curves[25].nid;

	for (int i = 0; i < crv_len; ++i)
	{
		printf("%d ", curves[i].nid);
		printf("%s\n", curves[i].comment);
	}

	// 根据选择的椭圆曲线生成密钥参数group
	group1 = EC_GROUP_new_by_curve_name(nid);
	if (NULL == group1)
	{
		printf("EC_GROUP_new_by_curve_name err\n");
		return -1;
	}
	group2 = EC_GROUP_new_by_curve_name(nid);
	if (NULL == group2)
	{
		printf("EC_GROUP_new_by_curve_name err\n");
		return -1;
	}

	// 设置密钥参数
	ret = EC_KEY_set_group(key1, group1);
	if (ret != 1)
	{
		printf("EC_KEY_set_group err\n");
		return -1;
	}
	ret = EC_KEY_set_group(key2, group2);
	if (ret != 1)
	{
		printf("EC_KEY_set_group err\n");
		return -1;
	}

	// 生成密钥
	ret = EC_KEY_generate_key(key1);
	if (ret != 1)
	{
		printf("EC_KEY_generate_key err\n");
		return -1;
	}
	ret = EC_KEY_generate_key(key2);
	if (ret != 1)
	{
		printf("EC_KEY_generate_key err\n");
		return -1;
	}

	// 检查密钥
	ret = EC_KEY_check_key(key1);
	if (ret != 1)
	{
		printf("EC_KEY_check_key err\n");
		return -1;
	}

	// 获取密钥大小
	size = ECDSA_size(key1);
	printf("size %d \n", size);
	for (i = 0; i < 20; ++i)
		memset(&digest[i], i + 1, 1);
	signature = (unsigned char *)malloc(size);
	ERR_load_crypto_strings();
	berr = BIO_new(BIO_s_file());

	// 签名数据，本例未做摘要，可将 digest 中的数据看作是 sha1 摘要结果
	ret = ECDSA_sign(0, digest, 20, signature, &sig_len, key1);
	if (ret != 1)
	{
		ERR_print_errors(berr);
		printf("sing err\n");
		return -1;
	}

	// 验证签名
	ret = ECDSA_verify(0, digest, 20, signature, sig_len, key1);
	if (ret != 1)
	{
		ERR_print_errors(berr);
		printf("ECDSA_verify err\n");
		return -1;
	}

	// 获取对方公钥，不能直接引用
	pubkey2 = EC_KEY_get0_public_key(key2);
	// 生成一方的共享密钥
	len1 = ECDH_compute_key(sharKey1, 128, pubkey2, key1, NULL);

	pubkey1 = EC_KEY_get0_public_key(key1);
	len2 = ECDH_compute_key(sharKey2, 128, pubkey1, key2, NULL);

	if (len1 != len2)
		printf("err\n");
	else
	{
		ret = memcmp(sharKey1, sharKey2, len1);
		if (0 == ret)
			printf("生成共享密钥成功\n");
		else
			printf("生成共享密钥失败\n");
	}

	printf("test ok\n");
	BIO_free(berr);
	EC_KEY_free(key1);
	EC_KEY_free(key2);
	free(signature);
	free(curves);

	return 0;
}
