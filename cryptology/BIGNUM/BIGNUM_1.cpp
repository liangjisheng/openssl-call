
// BN_ULONG(应系统而异，win32下为4个字节)数组指针首地址，大数就存放在这里面
// 不过是倒放的。比如，用户要存放的大数为12345678000（通过BN_bin2bn放入）
// 则d的内容如下：0x30 0x30 0x30 0x38 0x37 0x36 0x35 0x34 0x33 0x32 0x31
//struct bignum_st {
    //BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
    //                             * chunks. */
	// top用来指明大数占用多少个BN_ULONG空间
    //int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
	// d数组的大小
    //int dmax;                   /* Size of the d array. */
	// 正负判断
    //int neg;                    /* one if the number is negative */
	// 用于存放一些标记，比如flags含有BN_FLG_STATIC_DATA时，表明d的内存是
	// 静态分配的；含有BN_FLG_MALLOCED时，d的内存是动态分配的
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

	a = BN_new();		// 初始化为0
	bn_dec_printf(a);
	BN_one(a);			// 将a设置为1
	bn_dec_printf(a);
	w = 2685550010;
	ret = BN_add_word(a, w);	// 把w加到a上，返回1表示成功，其他失败
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
	// 将内存中的数据转换为大数，s为内存地址，len为数据长度，ret为返回值
	// BIGNUM* BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
	BIGNUM *ret1, *ret2;
	// 输入参数“242424ab”是asc码，对应的大数值为16进制的0x3234323432346162
	const unsigned char *data = (unsigned char *)"242424ab";
	ret1 = BN_new();
	// ret1和ret2是相同的数据
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
	// 将大数a转换为内存形式，to为输出缓冲区，缓冲区需要预先分配，返回值为缓冲区长度
	// int BN_bn2bin(const BIGNUM *a, unsigned char *to)

	BIGNUM *ret1 = NULL;
	unsigned char bin[50] = {0}, *buf = NULL;
	int len = 0;

	// 输入参数“242424ab”是asc码，对应的大数值为16进制的0x3234323432346162
	const unsigned char *data = (unsigned char *)"242424ab";
	ret1 = BN_bin2bn(data, 8, NULL);
	bn_hex_printf(ret1);
	len = BN_bn2bin(ret1, bin);
	printf("len = %d\n", len);

	// BN_num_bytes函数获取大数对应的缓冲区的大小
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

// BN_cmp()		// 比较两个大数
// 计算ax=1(mod n)
// BIGNUM *BN_mod_inverse(BIGNUM *in,  const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

void test_bignum1()
{
	test_2();
}

