
#include <iostream>
#include <cassert>
#include <string>
#include <vector>

#include "openssl\des.h"

using std::string;
using std::vector;
using std::cout;
using std::endl;

/**
 * function: 使用DES算法以ECB模式进行加密
 * param: clearText:明文, key:密钥
 * return: 密文
*/
string des_encrypt(const string& clearText, const string& key)
{
	string cipherText;

	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);

	// 构造补齐后的密钥
	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);

	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);

	// 循环加密，没8字节一次
	const_DES_cblock inputText;
	DES_cblock outputText;
	vector<unsigned char> vecCipherText;
	unsigned char tmp[8] = {0};

	for (string::size_type i = 0; i < clearText.length() / 8; ++i)
	{
		memcpy(inputText, clearText.c_str() + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; ++j)
			vecCipherText.push_back(tmp[j]);
	}

	if (clearText.length() % 8 != 0)
	{
		int tmp1 = clearText.length() / 8 * 8;
		int tmp2 = clearText.length() - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, clearText.c_str() + tmp1, tmp2);

		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
		memcpy(tmp, outputText, 8);

		for (int j = 0; j < 8; ++j)
			vecCipherText.push_back(tmp[j]);
	}

	cipherText.clear();
	cipherText.assign(vecCipherText.begin(), vecCipherText.end());

	return cipherText;
}

/**
 * function: 使用DES算法以ECB模式进行解密
 * param: cipherText:密文, key:密钥
 * return: 明文
*/
string des_decrypt(const string& cipherText, const string& key)
{
	string clearText;

	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);

	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);

	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);

	const_DES_cblock inputText;  
	DES_cblock outputText;  
	vector<unsigned char> vecCleartext;  
	unsigned char tmp[8]; 

	for (string::size_type i = 0; i < cipherText.length() / 8; i++)  
	{  
		memcpy(inputText, cipherText.c_str() + i * 8, 8);  
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);  
		memcpy(tmp, outputText, 8);  

		for (int j = 0; j < 8; j++)  
			vecCleartext.push_back(tmp[j]);  
	}

	if (cipherText.length() % 8 != 0)  
	{  
		int tmp1 = cipherText.length() / 8 * 8;  
		int tmp2 = cipherText.length() - tmp1;  
		memset(inputText, 0, 8);  
		memcpy(inputText, cipherText.c_str() + tmp1, tmp2);  
		// 解密函数    
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);  
		memcpy(tmp, outputText, 8);  

		for (int j = 0; j < 8; j++)  
			vecCleartext.push_back(tmp[j]);  
	}

	clearText.clear();
	clearText.assign(vecCleartext.begin(), vecCleartext.end());

	return clearText;
}

void test_DES_ECB()
{
	string srcText = "this is an example";
	string encryptText;
	string encryptHexText;
	string decryptText;

	cout << "原始字符串: " << endl;
	cout << srcText << endl;
	cout << "===DES加密解密===" << endl;
	string deskey = "12345";
	encryptText = des_encrypt(srcText, deskey);
	cout << "加密字符: " << endl;
	cout << encryptText << endl;
	decryptText = des_decrypt(encryptText, deskey);
	cout << "解密字符: " << endl;
	cout << decryptText << endl;
}

