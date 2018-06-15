
// BN_ULONG(Ӧϵͳ���죬win32��Ϊ4���ֽ�)����ָ���׵�ַ�������ʹ����������
// �����ǵ��ŵġ����磬�û�Ҫ��ŵĴ���Ϊ12345678000��ͨ��BN_bin2bn���룩
// ��d���������£�0x30 0x30 0x30 0x38 0x37 0x36 0x35 0x34 0x33 0x32 0x31
//struct bignum_st {
    //BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
    //                             * chunks. */
	// top����ָ������ռ�ö��ٸ�BN_ULONG�ռ�
    //int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
	// d����Ĵ�С
    //int dmax;                   /* Size of the d array. */
	// �����ж�
    //int neg;                    /* one if the number is negative */
	// ���ڴ��һЩ��ǣ�����flags����BN_FLG_STATIC_DATAʱ������d���ڴ���
	// ��̬����ģ�����BN_FLG_MALLOCEDʱ��d���ڴ��Ƕ�̬�����
    //int flags;
//};

#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>		// for memset

#ifdef _DEBUG
#include <vld.h>
#endif

void bn_printf(BIGNUM *a, int n);
void bn_hex_printf(BIGNUM * a);
void bn_dec_printf(BIGNUM * a);

static void test()
{
	int ret;
	BIGNUM *a;
	BN_ULONG w;

	a = BN_new();		// ��ʼ��Ϊ0
	bn_dec_printf(a);
	BN_one(a);			// ��a����Ϊ1
	bn_dec_printf(a);
	w = 2685550010;
	ret = BN_add_word(a, w);	// ��w�ӵ�a�ϣ�����1��ʾ�ɹ�������ʧ��
	if (ret != 1)
	{
		printf("a += w err\n");
		BN_free(a);
		return ;
	}

	bn_dec_printf(a);
	BN_free(a);
}

static void test_1()
{
	// ���ڴ��е�����ת��Ϊ������sΪ�ڴ��ַ��lenΪ���ݳ��ȣ�retΪ����ֵ
	// BIGNUM* BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
	BIGNUM *ret1, *ret2;
	// ���������242424ab����asc�룬��Ӧ�Ĵ���ֵΪ16���Ƶ�0x3234323432346162
	const unsigned char *data = (unsigned char *)"242424ab";
	ret1 = BN_new();
	// ret1��ret2����ͬ������
	ret1 = BN_bin2bn(data, 8, ret1);
	ret2 = BN_bin2bn(data, 8, NULL);

	bn_hex_printf(ret1);
	bn_hex_printf(ret2);
	bn_dec_printf(ret1);
	bn_dec_printf(ret2);

	BN_free(ret1);
	BN_free(ret2);
}

static void test_2()
{
	// ������aת��Ϊ�ڴ���ʽ��toΪ�������������������ҪԤ�ȷ��䣬����ֵΪ����������
	// int BN_bn2bin(const BIGNUM *a, unsigned char *to)

	BIGNUM *ret1 = NULL;
	unsigned char bin[50] = {0}, *buf = NULL;
	int len = 0;

	// ���������242424ab����asc�룬��Ӧ�Ĵ���ֵΪ16���Ƶ�0x3234323432346162
	const unsigned char *data = (unsigned char *)"242424ab";
	ret1 = BN_bin2bn(data, 8, NULL);
	bn_hex_printf(ret1);
	len = BN_bn2bin(ret1, bin);
	printf("len = %d\n", len);

	// BN_num_bytes������ȡ������Ӧ�Ļ������Ĵ�С
	len = BN_num_bytes(ret1);
	printf("len = %d\n", len);
	buf = (unsigned char *)malloc(len + 1);
	if (buf)
	{
		memset(buf, 0, len + 1);
		len = BN_bn2bin(ret1, buf);
		printf("%s\n", buf);
		printf("len = %d\n", len);
	}

	free(buf);
	BN_free(ret1);
}

// BN_cmp()		// �Ƚ���������
// ����ax=1(mod n)
// BIGNUM *BN_mod_inverse(BIGNUM *in,  const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

void test_bignum1()
{
	test_2();
}

