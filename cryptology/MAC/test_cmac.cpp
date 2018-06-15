
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/cmac.h>

#include "func.h"

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_cmac()
{
	int nRet = 0;
	// 密钥
	//string strKeyHexs = "6738e915cbff519cd89f5e408ea3ccaddf15efcecf0152a819f3c716cb947935";
	string strKeyHexs = "FE251C7858B356B24514B3BD5F4297D1";
	string strKeyBytes;
	MyHEX_BYTES(strKeyHexs, strKeyHexs.size(), strKeyBytes);
	int nLenKey = strKeyBytes.size();
	unsigned char *lpszKey = (unsigned char *)malloc(nLenKey + 1);
	memset(lpszKey, 0, nLenKey + 1);
	memcpy(lpszKey, strKeyBytes.c_str(), strKeyBytes.size());

	// 明文
	string strInputHexs = "7F494F060A04007F0007020204020286\
41042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD\
301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462";
	string strInputBytes;
	MyHEX_BYTES(strInputHexs, strInputHexs.size(), strInputBytes);

	unsigned int nDataLen = strInputBytes.size();
	// 当数据长度不是分组长度的整数倍时，不需要进行填充
	//if ((nDataLen % AES_BLOCK_SIZE) != 0)
	//	nDataLen = (nDataLen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	unsigned char *lpszInputData = (unsigned char *)malloc(nDataLen * sizeof(unsigned char));
	memset(lpszInputData, 0, nDataLen);
	memcpy(lpszInputData, strInputBytes.c_str(), strInputBytes.size());
	disp(lpszInputData, nDataLen);

	CMAC_CTX *ctx = CMAC_CTX_new();
	unsigned char szMAC[1024] = {0};
	size_t nLenMAC = 0;

	// 密钥长度必须和EVP_aes_128_cbc相对应，长度为128bits,否则CMAC_Init会失败
	//nRet = CMAC_Init(ctx, lpszKey, nLenKey, EVP_aes_256_cbc(), NULL);
	nRet = CMAC_Init(ctx, lpszKey, nLenKey, EVP_aes_128_cbc(), NULL);
	nRet = CMAC_Update(ctx, lpszInputData, nDataLen);
	nRet = CMAC_Final(ctx, szMAC, &nLenMAC);
	disp(szMAC, nLenMAC);

	CMAC_CTX_free(ctx);

	if (lpszKey)
	{
		free(lpszKey);
		lpszKey = NULL;
	}

	if (lpszInputData)
	{
		free(lpszInputData);
		lpszInputData = NULL;
	}
	return 0;
}

