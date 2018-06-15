
#include <stdio.h>
#include <string.h>

#ifdef _DEBUG
    #include <vld.h>
#endif

#include <openssl/rand.h>
#include <openssl/bn.h>

#include "func.h"

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);
void bn_hex_printf(const BIGNUM * a);
void bn_dec_printf(const BIGNUM * a);


void test()
{
	unsigned char szRandBytes[129] = {0};
	int nRet = RAND_bytes(szRandBytes, 48);
	disp(szRandBytes, 48);
	unsigned char szRandHexs[129] = {0};
	MyBYTES_HEX(szRandBytes, 48, szRandHexs);
	printf("%s\n", szRandHexs);

	BIGNUM *bnTerPriKey = BN_new();
	nRet = BN_hex2bn(&bnTerPriKey, (char *)szRandHexs);
	bn_hex_printf(bnTerPriKey);
}

