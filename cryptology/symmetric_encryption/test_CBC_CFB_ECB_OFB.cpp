
#include "encrypt.h"

void test_OFB()
{
	char szData[] = "Hello World!";
	char szEnData[16] = {0};
	char szDeData[16] = {0};
	char *lpszKey = "1234";
	int i = 0;
	char szIV[] = "9999";

	printf("ԭʼ����: %s\r\n", szData);

	while (true)
	{
		if (strlen(szData + i) == 0)
			break;

		// �����㷨�����
		Encrypt(szIV, lpszKey, szIV);

		// ���ķ����������㷨�������xor
		XorData(szData + i, szIV, szEnData + i);

		i += g_nBytesLen;
	}

	printf("���ܺ�����: %s\r\n", szEnData);

	memcpy(szIV, "9999", g_nBytesLen);
	i = 0;

	while (true)
	{
		if (strlen(szEnData + i) == 0)
			break;

		// �����㷨�����
		Encrypt(szIV, lpszKey, szIV);

		// ���ķ����������㷨�������XOR
		XorData(szEnData + i, szIV, szDeData + i);

		i += g_nBytesLen;
	}

	printf("���ܺ�����: %s\r\n", szDeData);
}

void test_ECB()
{
	char *lpszData = "Hello World!";
	char szEnData[16] = {0};
	char szDeData[16] = {0};
	char *lpszKey = "1234";
	int i = 0;

	printf("ԭʼ����: %s\r\n", lpszData);

	while (true)
	{
		if (strlen(lpszData + i) == 0)
			break;

		Encrypt(lpszData + i, lpszKey, szEnData + i);
		i += g_nBytesLen;
	}

	printf("���ܺ�����: %s\r\n", szEnData);

	i = 0;
	while (true)
	{
		if (strlen(szEnData + i) == 0)
			break;

		Decrypt(szEnData + i, lpszKey, szDeData + i);
		i += g_nBytesLen;
	}

	printf("���ܺ�����: %s\r\n", szDeData);
}

void test_CBC()
{
	// ���ı�������Կ���ȵı�����������ǣ�������벹0���ﵽ��Կ���ȵı���
	char szData[] = "Hello World!";
	char szEnData[16] = {0};
	char szDeData[16] = {0};
	char *lpszKey = "1234";
	int i = 0;
	char szIV[] = "9999";

	printf("ԭʼ����: %s\r\n", szData);
	printf("ԭʼ���ݳ���: %d\r\n", strlen(szData));

	while (true)
	{
		if (strlen(szData + i) == 0)
			break;

		// ��ǰһ�����ķ������xor
		XorEnGroup(szData + i, szIV, szData + i);

		// �������ķ���
		Encrypt(szData + i, lpszKey, szIV);

		memcpy(szEnData + i, szIV, g_nBytesLen);

		i += g_nBytesLen;
	}

	printf("���ܺ������: %s\r\n", szEnData);
	printf("���ܺ�����ݳ̶�: %d\n", strlen(szEnData));

	memcpy(szIV, "9999", g_nBytesLen);
	i = 0;
	char szPreEnData[8] = {0};

	while (true)
	{
		if (strlen(szEnData + i) == 0)
			break;

		memcpy(szPreEnData, szEnData + i, g_nBytesLen);

		// ����
		Decrypt(szEnData + i, lpszKey, szEnData + i);

		// ��ǰһ�����ķ������xor(���)
		XorEnGroup(szEnData + i, szIV, szDeData + i);

		memcpy(szIV, szPreEnData, g_nBytesLen);

		i += g_nBytesLen;
	}

	printf("���ܺ�����: %s\r\n", szDeData);
	printf("���ܺ����ݳ̶�: %d\r\n", strlen(szDeData));
}

void test_CFB()
{
	char szData[] = "Hello World!";
	char szEnData[16] = {0};
	char szDeData[16] = {0};
	char *lpszKey = "1234";
	int i = 0;
	char szIV[] = "9999";

	printf("ԭʼ����: %s\r\n", szData);

	while (true)
	{
		if (strlen(szData + i) == 0)
			break;

		// ��ǰһ�����ķ������
		Encrypt(szIV, lpszKey, szIV);

		// �����ķ���xor
		XorData(szData + i, szIV, szIV);

		memcpy(szEnData + i, szIV, g_nBytesLen);
		i += g_nBytesLen;
	}

	printf("���ܺ�����: %s\r\n", szEnData);

	memcpy(szIV, "9999", g_nBytesLen);
	i = 0;
	char szPreEnData[8] = {0};

	while (true)
	{
		if (strlen(szEnData + i) == 0)
			break;

		memcpy(szPreEnData, szEnData + i, g_nBytesLen);

		//��ǰһ�����ķ������, ע�������Ǽ���, �����ǽ���!!!!!!!!!!!!!!
		Encrypt(szIV, lpszKey, szIV);

		//�����ķ���xor�����õ�����
		XorData(szEnData + i, szIV, szDeData + i);

		memcpy(szIV, szPreEnData, g_nBytesLen);
		i += g_nBytesLen;
	}

	printf("���ܺ�����: %s\r\n", szDeData);
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

