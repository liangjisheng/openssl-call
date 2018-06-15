
// OpenSSLʵ�ֵ�ECC�㷨������������:ECC�㷨(crypto/ec),��Բ��������ǩ���㷨ECDSA(crypto/ecdsa)
// ��Բ������Կ�����㷨ECDH(crypto/dh)

// ��Բ������Կ����ʱ�������û���Ҫѡȡһ����Բ���ߣ�openssl������67�У�����EC_get_builtin_curves
// ��ȡ���б�Ȼ�����ѡ�����Բ���߼�����Կ���ɲ���group,��������Կ���ɲ��������㹫˽Կ

// ��ȡ��Բ�����б�
// size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)
// ����ָ������Բ������������Կ����
// EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
// ������Կ��������ECC��˽Կ
// int EC_KEY_generate_key(EC_KEY *eckey)
// ���ECC��Կ
// int EC_KEY_check_key(const EC_KEY *eckey)
// ��ȡ ECC ��Կ��С�ֽ���
// int ECDSA_size(const EC_KEY *r)

// ǩ��������1��ʾ�ɹ�
// int ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char
					// *sig, unsigned int *siglen, EC_KEY *eckey)
// ECDSA_sign_ex

// ��֤������1��ʾ�Ϸ�
// int ECDSA_verify(int type, const unsigned char *dgst, int dgst_len,
			// const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)

// ��ȡ��Կ
// EC_KEY_get0_public_key
// ��ȡ˽Կ
// EC_KEY_get0_private_key

// ���ɹ�����Կ
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

	// ����EC_KEY���ݽṹ
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

	// ��ȡ������Բ���߸���
	crv_len = EC_get_builtin_curves(NULL, 0);	// 67
	curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
	// ��ȡ������Բ�����б�
	EC_get_builtin_curves(curves, crv_len);

	// nid = curvers[0].nid;	// ���д�ԭ������Կ̫��
	// ѡȡһ����Բ����
	nid = curves[25].nid;

	for (int i = 0; i < crv_len; ++i)
	{
		printf("%d ", curves[i].nid);
		printf("%s\n", curves[i].comment);
	}

	// ����ѡ�����Բ����������Կ����group
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

	// ������Կ����
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

	// ������Կ
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

	// �����Կ
	ret = EC_KEY_check_key(key1);
	if (ret != 1)
	{
		printf("EC_KEY_check_key err\n");
		return -1;
	}

	// ��ȡ��Կ��С
	size = ECDSA_size(key1);
	printf("size %d \n", size);
	for (i = 0; i < 20; ++i)
		memset(&digest[i], i + 1, 1);
	signature = (unsigned char *)malloc(size);
	ERR_load_crypto_strings();
	berr = BIO_new(BIO_s_file());

	// ǩ�����ݣ�����δ��ժҪ���ɽ� digest �е����ݿ����� sha1 ժҪ���
	ret = ECDSA_sign(0, digest, 20, signature, &sig_len, key1);
	if (ret != 1)
	{
		ERR_print_errors(berr);
		printf("sing err\n");
		return -1;
	}

	// ��֤ǩ��
	ret = ECDSA_verify(0, digest, 20, signature, sig_len, key1);
	if (ret != 1)
	{
		ERR_print_errors(berr);
		printf("ECDSA_verify err\n");
		return -1;
	}

	// ��ȡ�Է���Կ������ֱ������
	pubkey2 = EC_KEY_get0_public_key(key2);
	// ����һ���Ĺ�����Կ
	len1 = ECDH_compute_key(sharKey1, 128, pubkey2, key1, NULL);

	pubkey1 = EC_KEY_get0_public_key(key1);
	len2 = ECDH_compute_key(sharKey2, 128, pubkey1, key2, NULL);

	if (len1 != len2)
		printf("err\n");
	else
	{
		ret = memcmp(sharKey1, sharKey2, len1);
		if (0 == ret)
			printf("���ɹ�����Կ�ɹ�\n");
		else
			printf("���ɹ�����Կʧ��\n");
	}

	printf("test ok\n");
	BIO_free(berr);
	EC_KEY_free(key1);
	EC_KEY_free(key2);
	free(signature);
	free(curves);

	return 0;
}
