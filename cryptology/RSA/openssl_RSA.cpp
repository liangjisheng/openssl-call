
#include <iostream>
#include <cassert>
#include <string>
#include <vector>

#include "openssl\rsa.h"
#include "openssl\pem.h"

using std::string;
using std::vector;
using std::cout;
using std::endl;

#define KEY_LENGTH 2048					// ��Կ����
#define PUB_KEY_FILE "pubkey.pem"		// ��Կ·��
#define PRI_KEY_FILE "prikey.pem"		// ˽Կ·��

// �����з������ɹ�˽Կ�ԣ�begin public key/ begin private key��  
// �ҵ�openssl�����й��ߣ���������  
// openssl genrsa -out prikey.pem 1024   
// openssl rsa - in privkey.pem - pubout - out pubkey.pem
/**
 * function: ������Կ��
 * param:
 * return: 
*/
void generateRSAKey(string strKey[2])
{
	// ��˽��Կ��
	size_t pri_len, pub_len;
	char *pri_key = NULL;
	char *pub_key = NULL;

	// ������Կ��
	RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	// ��ȡ����
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// ��Կ�Զ�ȡ���ַ���
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pri_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	// �洢��Կ��
	strKey[0] = pub_key;
	strKey[1] = pri_key;

	// �洢������(���ִ洢��ʽ��begin rsa public key/ begin rsa private key��ͷ��)
	FILE *pubFile = fopen(PUB_KEY_FILE, "w");
	if (pubFile == NULL)
	{
		assert(false);
		return ;
	}

	fputs(pub_key, pubFile);
	fclose(pubFile);

	FILE *priFile = fopen(PRI_KEY_FILE, "w");
	if (NULL == priFile)
	{
		assert(false);
		return ;
	}

	fputs(pri_key, priFile);
	fclose(priFile);

	// �ڴ��ͷ�
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);

	free(pri_key);
	free(pub_key);
}

/**
 * function: ��Կ����
 * param:
 * return: 
*/
string rsa_pub_encrypt(const string& clearText, const string& pubKey)
{
	string strRet;
	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pubKey.c_str(), -1);

	// �˴���3�з���
	// 1.��ȡ�ڴ������ɵ���Կ�ԣ��ٴ��ڴ�����rsa
	// 2.��ȡ���������ɵ���Կ���ı��ļ����ڴ��ڴ�����rsa
	// 3.ֱ�ӴӶ�ȡ�ļ�ָ������rsa
	RSA* pRSAPublicKey = RSA_new();
	rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	// ���ܺ���
	int ret = RSA_public_encrypt(clearText.length(), (const unsigned char *)clearText.c_str(),
		(unsigned char *)encryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = string(encryptedText, ret);

	// �ͷ��ڴ�
	free(encryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

/**
 * function: ˽Կ����
 * param:
 * return: 
*/
string rsa_pri_decrypt(const string& cipherText, const string& priKey)
{
	string strRet;
	RSA *rsa = RSA_new();
	BIO *keybio;
	keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);

	// �˴���3�з���
	// 1.��ȡ�ڴ������ɵ���Կ�ԣ��ٴ��ڴ�����rsa
	// 2.��ȡ���������ɵ���Կ���ı��ļ����ڴ��ڴ�����rsa
	// 3.ֱ�ӴӶ�ȡ�ļ�ָ������rsa
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	// ���ܺ���
	int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char *)cipherText.c_str(),
		(unsigned char *)decryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = string(decryptedText, ret);

	// �ͷ��ڴ�
	free(decryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

void test_RSA()
{
	string srcText = "this is an example";
	string encryptText;  
	string encryptHexText;  
	string decryptText;

	cout << "ԭʼ����: " << endl;
	cout << srcText << endl;

	cout << "===rsa���ܽ���===" << endl;
	string key[2];
	generateRSAKey(key);
	cout << "��Կ: " << endl;
	cout << key[0] << endl;
	cout << "˽Կ: " << endl;
	cout << key[1] << endl;

	encryptText = rsa_pub_encrypt(srcText, key[0]);
	cout << "�����ַ�: " << endl;
	cout << encryptText <<endl;

	decryptText = rsa_pri_decrypt(encryptText, key[1]);
	cout << "�����ַ�: " << endl;
	cout << decryptText << endl;
}

