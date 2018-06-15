
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
 *������ܿ���ֽڳ���
*/
const int g_nBytesLen = 4;

/**
 * function: �����㷨(��Key���)
 * param: lpszData:���ķ�������, lpszKey:��Կ, lpszEnData:���ܺ�Ľ��
 * return: 
*/
void Encrypt(IN const char* lpszData, IN const char* lpszKey, OUT char* lpszEnData)
{
	int i = 0;
	for (i = 0; i < g_nBytesLen; ++i)
		lpszEnData[i] = lpszData[i] ^ lpszKey[i];
}

/**
 * function: �����㷨(�ٴ����ԭ����)
 * param: lpszData: ��ǰ���ķ�������, lpszKey: ��Կ, lpszDeData: ���ܺ�Ľ��
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
 * function: ��ǰһ�����ķ������xor(���)
 * param: lpszData: ��ǰ���ķ������ݣ�lpszPreEnData: ǰһ�����ķ��飬lpszDeData: �������������
 * return: 
*/
void XorEnGroup(IN const char* lpszData, IN const char* lpszPreEnData, OUT char* lpszDeData)
{
	int i = 0;
	for (i = 0; i < g_nBytesLen; ++i)
		lpszDeData[i] = lpszData[i] ^ lpszPreEnData[i];
}

#endif  //__ENCRYP_H__
