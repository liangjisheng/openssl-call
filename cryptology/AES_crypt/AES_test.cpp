
// 使用OpenSSL进行AES加密和解密

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "func.h"

#ifdef _DEBUG
	#include <vld.h>
#endif

#include <openssl\aes.h>

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

void AES_CBC(const int nKeyLen);

void AES_CBC_128_1();

void AES_ECB(const int nKeyLen);


int main(int argc, char** argv)
{
	//AES_CBC(128);
	//AES_CBC(192);
	AES_CBC(256);

	//AES_CBC_128_1();

	//AES_ECB(128);
	//AES_ECB(192);
	//AES_ECB(256);

	//int nIndex= 0;
	//int nKeyLen = 384;
	//unsigned char szTokenHexs[1024] = {0};
	//memcpy(szTokenHexs + nIndex, "7F494F", strlen("7F494F"));
	//nIndex += strlen("7F494F");

	//unsigned char szchByte = 0x86;
	//unsigned char szchHexs[4] = {0};
	//MyBYTES_HEX(&szchByte, 1, szchHexs);
	//memcpy(szTokenHexs + nIndex, szchHexs, strlen((char *)szchHexs));
	//nIndex += strlen((char *)szchHexs);

	//szchByte = (nKeyLen / 8) * 2 + 1;
	//memset(szchHexs, 0, sizeof(szchHexs));
	//MyBYTES_HEX(&szchByte, 1, szchHexs);
	//memcpy(szTokenHexs + nIndex, szchHexs, strlen((char *)szchHexs));
	//nIndex += strlen((char *)szchHexs);

	//szchByte = 0x04;
	//memset(szchHexs, 0, sizeof(szchHexs));
	//MyBYTES_HEX(&szchByte, 1, szchHexs);
	//memcpy(szTokenHexs + nIndex, szchHexs, strlen((char *)szchHexs));
	//nIndex += strlen((char *)szchHexs);

	//string strHexs = "fef74e46beb192f04d7e0cf93fde0bfa";
	//string strBytes;
	//MyHEX_BYTES(strHexs, strHexs.size(), strBytes);
	//unsigned char sz[32] = {0};
	//for (size_t i = 0; i < strBytes.size(); ++i)
	//	sz[i] = strBytes[i];

	system("pause");
	return 0;
}

void AES_CBC(const int nKeyLen)
{
	//string strKeyHexs = "89ded1b26624ec1e634c1989302849dd";
	//string strKeyBytes;
	//MyHEX_BYTES(strKeyHexs, strKeyHexs.size(), strKeyBytes);

	// encrypt length (in multiple of AES_BLOCK_SIZE)
	// 明文长度，必须为密钥长度的倍数
	//unsigned int len = strKeyBytes.size();
	//if ((len % (nKeyLen / 8)) != 0)
	//	len = (len / (nKeyLen / 8) + 1) * (nKeyLen / 8);

	// 密钥
	unsigned char *lpszKey = (unsigned char *)malloc((nKeyLen / 8) * sizeof(unsigned char));
	memset(lpszKey, 0, nKeyLen / 8);
	string strKeyHexs("4ecccbb0cf183d78cd1832695cc9c16bd327e895eb330cc6a6aad1858fbca45c");
	string strKeyBytes;
	MyHEX_BYTES(strKeyHexs, strKeyHexs.size(), strKeyBytes);
	memcpy(lpszKey, strKeyBytes.c_str(), strKeyBytes.size());

	// 明文
	//string strInputHexs = "3f00c4d39d153f2b2a214a078d989b22ffff";
	//string strInputHexs = "011E800000000000";
	string strInputHexs = "011E8000000000000000000000000000";
	string strInputBytes;
	MyHEX_BYTES(strInputHexs, strInputHexs.size(), strInputBytes);

	unsigned int nDataLen = strInputBytes.size();
	//if ((nDataLen % (nKeyLen / 8)) != 0)
	//	nDataLen = (nDataLen / (nKeyLen / 8) + 1) * (nKeyLen / 8);
	if ((nDataLen % AES_BLOCK_SIZE) != 0)
		nDataLen = (nDataLen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	//nDataLen = (nDataLen + 7) / 8 * 8;
	unsigned char *lpszInputData = (unsigned char *)malloc(nDataLen * sizeof(unsigned char));
	memset(lpszInputData, 0, nDataLen);
	memcpy(lpszInputData, strInputBytes.c_str(), strInputBytes.size());
	disp(lpszInputData, nDataLen);

	AES_KEY aes;
	memset(&aes, 0, sizeof(AES_KEY));

	int nRet = -1;
	nRet = AES_set_encrypt_key(lpszKey, nKeyLen, &aes);
	if (nRet < 0)
	{
		fprintf(stderr, "Unable to set encryption key in AES\n");
		exit(-1);
	}
	
	// alloc encrypt string
	unsigned char *lpszEncryptData = (unsigned char *)malloc(nDataLen + 1);
	memset(lpszEncryptData, 0, nDataLen + 1);

	// 初始化向量的长度不管是nDataLen还是AES_BLOCK_SIZE对加密的结果都不影响
	unsigned char *lpszIVData = (unsigned char *)malloc(AES_BLOCK_SIZE + 1);
	memset(lpszIVData, 0, AES_BLOCK_SIZE + 1);
	string strIVBytes, strIVHexs("d3b8513544e9289901d9354fec40f991");
	MyHEX_BYTES(strIVHexs, strIVHexs.size(), strIVBytes);
	memcpy(lpszIVData, strIVBytes.c_str(), strIVBytes.size());
	
	// encrypt (iv will change)
	// 每次加密16个字节或者一次全部加密完成都可以，所有这个for循环和下面的那句话是等价的
	//for (unsigned int i = 0; i < nDataLen / AES_BLOCK_SIZE; ++i)
	//{
	//	AES_cbc_encrypt(lpszInputData + i * AES_BLOCK_SIZE, lpszEncryptData + i * AES_BLOCK_SIZE, 
	//		AES_BLOCK_SIZE,	&aes, lpszIVData, AES_ENCRYPT);
	//}
	AES_cbc_encrypt(lpszInputData, lpszEncryptData, nDataLen, &aes, lpszIVData, AES_ENCRYPT);
	disp(lpszEncryptData, nDataLen);

	// alloc decrypt_string
	unsigned char *lpszDecryptData = (unsigned char *)malloc(nDataLen * sizeof(unsigned char));
	memset(lpszDecryptData, 0, nDataLen);

	memset(&aes, 0, sizeof(AES_KEY));
	if (AES_set_decrypt_key(lpszKey, nKeyLen, &aes) < 0)
	{
		fprintf(stderr, "Unable to set decryption key in AES\n");
		exit(-1);
	}

	// 恢复初始化向量为0
	memset(lpszIVData, 0, nDataLen);
	// decrypt
	//for (unsigned int i = 0; i < nDataLen / AES_BLOCK_SIZE; ++i)
	//{
	//	AES_cbc_encrypt(lpszEncryptData + i * AES_BLOCK_SIZE, lpszDecryptData + i * AES_BLOCK_SIZE,
	//		AES_BLOCK_SIZE, &aes, lpszIVData, AES_DECRYPT);
	//}
	AES_cbc_encrypt(lpszEncryptData, lpszDecryptData, nDataLen, &aes, lpszIVData, AES_DECRYPT);
	disp(lpszDecryptData, nDataLen);
	printf("\n");

	//unsigned int i = 0;
	//// print
	//printf("input_string string = ");
	//for (i = 0; i < nDataLen; ++i)
	//	printf("%x%x", (lpszInputData[i] >> 4) & 0xf, lpszInputData[i] & 0xf);
	//printf("\n");

	//printf("encrypted string = ");
	//for (i = 0; i < nDataLen; ++i)
	//	printf("%x%x", (lpszEncryptData[i] >> 4) & 0xf, lpszEncryptData[i] & 0xf);
	//printf("\n");

	//printf("decrypted string = ");
	//for (i = 0; i < nDataLen; ++i)
	//	printf("%x%x", (lpszDecryptData[i] >> 4) & 0xf, lpszDecryptData[i] & 0xf);
	//printf("\n");

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

	if (lpszEncryptData)
	{
		free(lpszEncryptData);
		lpszEncryptData = NULL;
	}

	if (lpszDecryptData)
	{
		free(lpszDecryptData);
		lpszDecryptData = NULL;
	}
}

void AES_CBC_128_1()
{
	char source[1024] = {0};
	strcpy(source, "1234567890abcdef");
	unsigned char *InputData = NULL;
	unsigned char *EncryptData = NULL;

	unsigned char Key[AES_BLOCK_SIZE + 1] = {0};
	memcpy(Key, "0123456789abcdef", AES_BLOCK_SIZE);
	unsigned char ivec[AES_BLOCK_SIZE] = {0};

	AES_KEY AesKey;
	int DataLen = strlen(source), SetDataLen = 0, i = 0;

	// set the encryption length
	if ((DataLen % AES_BLOCK_SIZE) == 0)
		SetDataLen = DataLen;
	else
		SetDataLen = ((DataLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	printf("SetDataLen: %d...\n", SetDataLen);	// 取16的倍数

	InputData = (unsigned char *)calloc(SetDataLen + 1, sizeof(unsigned char));
	memset(InputData, 0, SetDataLen + 1);
	memcpy(InputData, source, DataLen);
	disp(InputData, SetDataLen);
	EncryptData = (unsigned char *)calloc(SetDataLen + 1, sizeof(unsigned char));
	memset(EncryptData, 0, SetDataLen + 1);

	memset(&AesKey, 0, sizeof(AES_KEY));
	// 设置加密密钥
	if (AES_set_encrypt_key(Key, 128, &AesKey) < 0)
	{
		fprintf(stderr, "Unable to set encryption key in AES...\n");
		exit(-1);
	}

	// 加密
	AES_cbc_encrypt(InputData, EncryptData, SetDataLen,	&AesKey, ivec, AES_ENCRYPT);
	disp(EncryptData, SetDataLen);

	memset(&AesKey, 0, sizeof(AES_KEY));
	// 设置解密密钥
	if (AES_set_decrypt_key(Key, 128, &AesKey) < 0)
	{
		fprintf(stderr, "Unable to set decryption key in AES...\n");
		exit(-1);
	}

	memset(ivec, 0, AES_BLOCK_SIZE);
	// 解密
	unsigned char *DecryptData = NULL;
	DecryptData = (unsigned char *)calloc(SetDataLen + 1, sizeof(unsigned char));
	memset(DecryptData, 0, SetDataLen + 1);
	AES_cbc_encrypt(EncryptData, DecryptData, SetDataLen, &AesKey, ivec, AES_DECRYPT);
	disp(DecryptData, SetDataLen);

	if (InputData != NULL)
	{
		free(InputData);
		InputData = NULL;
	}

	if (EncryptData != NULL)
	{
		free(EncryptData);
		EncryptData = NULL;
	}

	if (DecryptData != NULL)
	{
		free(DecryptData);
		DecryptData = NULL;
	}
}

void AES_ECB(const int nKeyLen)
{
	unsigned char szData[1024] = {0};
	memcpy(szData, "1234567890abcdefzzzz", strlen("1234567890abcdefzzzz"));

	// 设置明文长度为16的倍数
	int nDataLen = strlen((char *)szData);
	int nSetDataLen = 0;
	//if (nDataLen % AES_BLOCK_SIZE == 0)
	//	nSetDataLen = nDataLen;
	//else
	//	nSetDataLen = (nDataLen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	if (nDataLen % AES_BLOCK_SIZE == 0)
		nSetDataLen = nDataLen;
	else
		nSetDataLen = (nDataLen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

	// 明文
	unsigned char *lpszInputData = (unsigned char *)malloc(nSetDataLen * sizeof(unsigned char));
	memset(lpszInputData, 0, nSetDataLen);
	memcpy(lpszInputData, szData, nSetDataLen);
	printf("InputData: ");
	disp(lpszInputData, nSetDataLen);

	AES_KEY AesKey;
	memset(&AesKey, 0, sizeof(AES_KEY));

	// 密钥默认使用全是0,
	unsigned char *lpszKey = (unsigned char *)malloc(nKeyLen / 8 * sizeof(unsigned char));
	memset(lpszKey, 0, nKeyLen / 8);
	//unsigned char szKey[AES_BLOCK_SIZE + 1] = {0};
	//memcpy(szKey, "0123456789abcdef", strlen("0123456789abcdef"));

	if (AES_set_encrypt_key(lpszKey, nKeyLen, &AesKey) < 0)
	{
		fprintf(stderr, "AES_set_encrypt_key error\n");
		exit(-1);
	}

	unsigned char *lpszEncryptData = (unsigned char *)malloc(nSetDataLen * sizeof(unsigned char));
	memset(lpszEncryptData, 0, nSetDataLen);

	for (int i = 0; i < nSetDataLen / AES_BLOCK_SIZE; ++i)
	{
		AES_ecb_encrypt(lpszInputData + i * AES_BLOCK_SIZE, lpszEncryptData + i * AES_BLOCK_SIZE, 
			&AesKey, AES_ENCRYPT);
	}
	printf("EncryptData: ");
	disp(lpszEncryptData, nSetDataLen);

	unsigned char *lpszDecryptData = (unsigned char *)malloc(nSetDataLen * sizeof(unsigned char));
	memset(lpszDecryptData, 0, nSetDataLen);

	memset(&AesKey, 0, sizeof(AES_KEY));
	if (AES_set_decrypt_key(lpszKey, nKeyLen, &AesKey) < 0)
	{
		fprintf(stderr, "AES_set_encrypt_key error\n");
		exit(-1);
	}

	for (int i = 0; i < nSetDataLen / AES_BLOCK_SIZE; ++i)
	{
		AES_ecb_encrypt(lpszEncryptData + i * AES_BLOCK_SIZE, lpszDecryptData + i * AES_BLOCK_SIZE,
			&AesKey, AES_DECRYPT);
	}
	printf("DecryptData: ");
	disp(lpszDecryptData, nSetDataLen);
	printf("\n");

	if (NULL != lpszInputData)
	{
		free(lpszInputData);
		lpszInputData = NULL;
	}

	if (NULL != lpszEncryptData)
	{
		free(lpszEncryptData);
		lpszEncryptData = NULL;
	}

	if (NULL != lpszDecryptData)
	{
		free(lpszDecryptData);
		lpszDecryptData = NULL;
	}

	if (NULL != lpszKey)
	{
		free(lpszKey);
		lpszKey = NULL;
	}
}

