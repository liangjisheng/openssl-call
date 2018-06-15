
// http://www.cnblogs.com/dacainiao/p/5525364.html
// http://www.cnblogs.com/dacainiao/p/5521930.html

#ifndef __ENCRYP_H__
#define __ENCRYP_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IN
#define OUT

/**
 *分组加密块的字节长度
*/
const int g_nBytesLen = 4;

/**
 * function: 加密算法(与Key异或)
 * param: lpszData:明文分组数据, lpszKey:密钥, lpszEnData:加密后的结果
 * return: 
*/
void Encrypt(IN const char* lpszData, IN const char* lpszKey, OUT char* lpszEnData)
{
	int i = 0;
	for (i = 0; i < g_nBytesLen; ++i)
		lpszEnData[i] = lpszData[i] ^ lpszKey[i];
}

/**
 * function: 解密算法(再次异或还原明文)
 * param: lpszData: 当前密文分组数据, lpszKey: 密钥, lpszDeData: 解密后的结果
 * return: 
*/
void Decrypt(IN const char* lpszData, IN const char* lpszKey, OUT char* lpszDeData)
{
	int i = 0;
	for (i = 0; i < g_nBytesLen; ++i)
		lpszDeData[i] = lpszData[i] ^ lpszKey[i];
}

void XorData(IN const char* lpszData, IN const char* lpszKeyStream, OUT char* lpszXorData)
{
	int i = 0;
	for (i = 0; i < g_nBytesLen; ++i)
		lpszXorData[i] = lpszData[i] ^ lpszKeyStream[i];
}

/**
 * function: 与前一个密文分组进行xor(异或)
 * param: lpszData: 当前明文分组数据，lpszPreEnData: 前一个密文分组，lpszDeData: 保存异或后的数据
 * return: 
*/
void XorEnGroup(IN const char* lpszData, IN const char* lpszPreEnData, OUT char* lpszDeData)
{
	int i = 0;
	for (i = 0; i < g_nBytesLen; ++i)
		lpszDeData[i] = lpszData[i] ^ lpszPreEnData[i];
}

#endif  //__ENCRYP_H__
