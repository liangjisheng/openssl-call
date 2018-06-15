
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/evp.h>

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

void test_ecb()
{
	unsigned char szUserKey[AES_BLOCK_SIZE] = {0};
	unsigned char *lpszDate = (unsigned char *)malloc(AES_BLOCK_SIZE * 3);
	unsigned char *lpszEncrypt = (unsigned char *)malloc(AES_BLOCK_SIZE * 3 + 4);
	unsigned char *lpszPlain = (unsigned char *)malloc(AES_BLOCK_SIZE * 3);
	AES_KEY key;

	memset(szUserKey, 'k', AES_BLOCK_SIZE);
	memset(lpszDate, 'p', AES_BLOCK_SIZE * 3);
	memset(lpszEncrypt, 0, AES_BLOCK_SIZE * 3 + 4);
	memset(lpszPlain, 0, AES_BLOCK_SIZE * 3);

	printf("key: ");
	disp(szUserKey, AES_BLOCK_SIZE);
	printf("data: ");
	disp(lpszDate, AES_BLOCK_SIZE * 3);
	printf("Encrypt: ");
	disp(lpszEncrypt, AES_BLOCK_SIZE * 3 + 4);
	printf("plain: ");
	disp(lpszPlain, AES_BLOCK_SIZE * 3);
	printf("\n");

	// ���ü���key����Կ����
	AES_set_encrypt_key(szUserKey, AES_BLOCK_SIZE * 8, &key);

	int len = 0;
	// ѭ�����ܣ�AES_encryptÿ��ֻ�ܼ���AES_BLOCK_SIZE���ȵ�����
	while (len < AES_BLOCK_SIZE * 3)
	{
		AES_encrypt(lpszDate + len, lpszEncrypt + len, &key);
		len += AES_BLOCK_SIZE;
	}

	printf("Encrypt: ");
	disp(lpszEncrypt, AES_BLOCK_SIZE * 3 + 4);

	// ���ý���key����Կ����
	AES_set_decrypt_key(szUserKey, AES_BLOCK_SIZE * 8, &key);
	len = 0;
	while (len < AES_BLOCK_SIZE * 3)
	{
		AES_decrypt(lpszEncrypt + len, lpszPlain + len, &key);
		len += AES_BLOCK_SIZE;
	}

	printf("plain: ");
	disp(lpszPlain, AES_BLOCK_SIZE * 3);

	// ���ܺ���ԭ�����Ƿ�һ��
	if (0 == memcmp(lpszPlain, lpszDate, AES_BLOCK_SIZE * 3))
		printf("test success\n");
	else
		printf("test failed\n");

	if (lpszDate)
	{
		free(lpszDate);
		lpszDate = NULL;
	}

	if (lpszEncrypt)
	{
		free(lpszEncrypt);
		lpszEncrypt = NULL;
	}

	if (lpszPlain)
	{
		free(lpszPlain);
		lpszPlain = NULL;
	}
}

void test_EVP_ecb()
{
	unsigned char szUserKey[EVP_MAX_KEY_LENGTH] = {0};
	unsigned char szIV[EVP_MAX_IV_LENGTH] = {0};
	unsigned char *lpszData = (unsigned char *)malloc(AES_BLOCK_SIZE * 3);
	unsigned char *lpszEncrypt = (unsigned char *)malloc(AES_BLOCK_SIZE * 6);
	unsigned char *lpszPlain = (unsigned char *)malloc(AES_BLOCK_SIZE * 6);
	EVP_CIPHER_CTX ctx;
	int ret = 0, tlen = 0, mlen = 0, flen = 0;
	
	memset(szUserKey, 'k', EVP_MAX_KEY_LENGTH);
	memset(szIV, 'i', EVP_MAX_IV_LENGTH);
	memset(lpszData, 'p', AES_BLOCK_SIZE * 3);
	memset(lpszEncrypt, 0, AES_BLOCK_SIZE * 6);
	memset(lpszPlain, 0, AES_BLOCK_SIZE * 6);

	printf("key: ");
	disp(szUserKey, AES_BLOCK_SIZE);
	printf("data: ");
	disp(lpszData, AES_BLOCK_SIZE * 3);
	printf("Encrypt: ");
	disp(lpszEncrypt, AES_BLOCK_SIZE * 3 + 4);
	printf("plain: ");
	disp(lpszPlain, AES_BLOCK_SIZE * 3);
	printf("\n");

	// ��ʼ��ctx
	EVP_CIPHER_CTX_init(&ctx);

	// ָ�������㷨��key��iv(�˴�ivû����)
	ret = EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, szUserKey, szIV);
	if (1 != ret)
	{
		printf("EVP_EncryptInit_ex failed\n");
		exit(-1);
	}

	// �������(padding)����
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	// ����
	ret = EVP_EncryptUpdate(&ctx, lpszEncrypt, &mlen, lpszData, AES_BLOCK_SIZE * 3);
	if (1 != ret)
	{
		printf("EVP_EncryptUpdate failed\n");
		exit(-1);
	}

	printf("Encrypt: ");
	disp(lpszEncrypt, AES_BLOCK_SIZE * 3 + 4);

	// �������ܲ���
	ret = EVP_EncryptFinal_ex(&ctx, lpszEncrypt + mlen, &flen);
	if (1 != ret)
	{
		printf("EVP_EncryptFinal_ex failed\n");
		exit(-1);
	}

	tlen = mlen + flen;
	tlen = mlen = flen = 0;
	EVP_CIPHER_CTX_cleanup(&ctx);

	EVP_CIPHER_CTX_init(&ctx);
	ret = EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, szUserKey, szIV);
	if (1 != ret)
	{
		printf("EVP_DecryptInit_ex failed\n");
		exit(-1);
	}

	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	ret = EVP_DecryptUpdate(&ctx, lpszPlain, &mlen, lpszEncrypt, AES_BLOCK_SIZE * 3);
	if (1 != ret)
	{
		printf("EVP_DecryptUpdate failed\n");
		exit(-1);
	}

	printf("plain: ");
	disp(lpszPlain, AES_BLOCK_SIZE * 3);

	ret == EVP_DecryptFinal_ex(&ctx, lpszPlain + mlen, &flen);
	if (1 != ret)
	{
		printf("EVP_DecryptFinal_ex failed\n");
		exit(-1);
	}

	// ���ܺ�������ԭ���ݶԱ�
	if (0 == memcmp(lpszPlain, lpszData, AES_BLOCK_SIZE * 3))
		printf("test success\n");
	else
		printf("test failed\n");
}

int main()
{
	//test_ecb();
	//test_EVP_ecb();

	getchar();
	return 0;
}

