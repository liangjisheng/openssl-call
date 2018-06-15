
#include "encrypt.h"

void test_OFB()
{
	char szData[] = "Hello World!";
	char szEnData[16] = {0};
	char szDeData[16] = {0};
	char *lpszKey = "1234";
	int i = 0;
	char szIV[] = "9999";

	printf("原始数据: %s\r\n", szData);

	while (true)
	{
		if (strlen(szData + i) == 0)
			break;

		// 密码算法的输出
		Encrypt(szIV, lpszKey, szIV);

		// 明文分组与密码算法的输出做xor
		XorData(szData + i, szIV, szEnData + i);

		i += g_nBytesLen;
	}

	printf("加密后数据: %s\r\n", szEnData);

	memcpy(szIV, "9999", g_nBytesLen);
	i = 0;

	while (true)
	{
		if (strlen(szEnData + i) == 0)
			break;

		// 密码算法的输出
		Encrypt(szIV, lpszKey, szIV);

		// 密文分组与密码算法的输出做XOR
		XorData(szEnData + i, szIV, szDeData + i);

		i += g_nBytesLen;
	}

	printf("解密后数据: %s\r\n", szDeData);
}

void test_ECB()
{
	char *lpszData = "Hello World!";
	char szEnData[16] = {0};
	char szDeData[16] = {0};
	char *lpszKey = "1234";
	int i = 0;

	printf("原始数据: %s\r\n", lpszData);

	while (true)
	{
		if (strlen(lpszData + i) == 0)
			break;

		Encrypt(lpszData + i, lpszKey, szEnData + i);
		i += g_nBytesLen;
	}

	printf("加密后数据: %s\r\n", szEnData);

	i = 0;
	while (true)
	{
		if (strlen(szEnData + i) == 0)
			break;

		Decrypt(szEnData + i, lpszKey, szDeData + i);
		i += g_nBytesLen;
	}

	printf("解密后数据: %s\r\n", szDeData);
}

void test_CBC()
{
	// 明文必须是密钥长度的倍数，如果不是，后面必须补0，达到密钥长度的倍数
	char szData[] = "Hello World!";
	char szEnData[16] = {0};
	char szDeData[16] = {0};
	char *lpszKey = "1234";
	int i = 0;
	char szIV[] = "9999";

	printf("原始数据: %s\r\n", szData);
	printf("原始数据长度: %d\r\n", strlen(szData));

	while (true)
	{
		if (strlen(szData + i) == 0)
			break;

		// 与前一个密文分组进行xor
		XorEnGroup(szData + i, szIV, szData + i);

		// 更新密文分组
		Encrypt(szData + i, lpszKey, szIV);

		memcpy(szEnData + i, szIV, g_nBytesLen);

		i += g_nBytesLen;
	}

	printf("加密后的数据: %s\r\n", szEnData);
	printf("加密后的数据程度: %d\n", strlen(szEnData));

	memcpy(szIV, "9999", g_nBytesLen);
	i = 0;
	char szPreEnData[8] = {0};

	while (true)
	{
		if (strlen(szEnData + i) == 0)
			break;

		memcpy(szPreEnData, szEnData + i, g_nBytesLen);

		// 解密
		Decrypt(szEnData + i, lpszKey, szEnData + i);

		// 与前一个密文分组进行xor(异或)
		XorEnGroup(szEnData + i, szIV, szDeData + i);

		memcpy(szIV, szPreEnData, g_nBytesLen);

		i += g_nBytesLen;
	}

	printf("解密后数据: %s\r\n", szDeData);
	printf("解密后数据程度: %d\r\n", strlen(szDeData));
}

void test_CFB()
{
	char szData[] = "Hello World!";
	char szEnData[16] = {0};
	char szDeData[16] = {0};
	char *lpszKey = "1234";
	int i = 0;
	char szIV[] = "9999";

	printf("原始数据: %s\r\n", szData);

	while (true)
	{
		if (strlen(szData + i) == 0)
			break;

		// 与前一个密文分组加密
		Encrypt(szIV, lpszKey, szIV);

		// 与明文分组xor
		XorData(szData + i, szIV, szIV);

		memcpy(szEnData + i, szIV, g_nBytesLen);
		i += g_nBytesLen;
	}

	printf("加密后数据: %s\r\n", szEnData);

	memcpy(szIV, "9999", g_nBytesLen);
	i = 0;
	char szPreEnData[8] = {0};

	while (true)
	{
		if (strlen(szEnData + i) == 0)
			break;

		memcpy(szPreEnData, szEnData + i, g_nBytesLen);

		//与前一个密文分组加密, 注意这里是加密, 而不是解密!!!!!!!!!!!!!!
		Encrypt(szIV, lpszKey, szIV);

		//与密文分组xor操作得到明文
		XorData(szEnData + i, szIV, szDeData + i);

		memcpy(szIV, szPreEnData, g_nBytesLen);
		i += g_nBytesLen;
	}

	printf("解密后数据: %s\r\n", szDeData);
}


int main()
{
	//test_ECB();
	//test_CBC();
	//test_CFB();
	//test_OFB();

	getchar();
	return 0;
}

