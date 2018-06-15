
#ifndef __FUNC_H__
#define __FUNC_H__

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>

using namespace std;

// define a special type for such strings
typedef std::basic_string<unsigned char> ucstring;

inline std::ostream& operator << (std::ostream& strm, const ucstring& s)
{
	for (ucstring::size_type i = 0; i < s.size(); ++i)
		strm << s[i];
	return strm;
}

/**
 * function: ��һ��16���Ʊ�ʾ���ַ�ת��Ϊ��Ӧ������
 * param: c: 16���Ʊ�ʾ���ַ�, d:��ʾ���������
 * return: None
*/
void My16cTo10(unsigned char c,unsigned int &d);

/**
 * function: ��һ��������ʾΪ��Ӧ��16�����ַ�
 * param: d: ������c:16�����ַ�
 * return: None
*/
void My10To16(unsigned int d, unsigned char& c);

/**
 * function: ��16�����ַ���ʾ���ַ���ת��Ϊ�޷��ŵ���ͨ�ַ���
 *			 ������洢��strBytes��
 * param: strHexs: 16���Ʊ�ʾ���ַ���
 *		  strHexLen: ����С��strHexs.size(),�����ܳ�����������Ϊż��
 * return: None
*/
void MyHEX_BYTES(const string& strHexs, int strHexLen, string& strBytes);

/**
 * function: ��16�����ַ���ʾ���ַ���ת��Ϊ�޷��ŵ���ͨ�ַ���
 *			 ������洢��strBytes��
 * param: strHexs: 16���Ʊ�ʾ���ַ���
 *		  strHexLen: ����С��strHexs.size(),�����ܳ�����������Ϊż��
 * return: None
*/
void MyHEX_BYTES(const ucstring& strHexs, int strHexLen, ucstring& strBytes);

/**
 * function: ��16�����ַ���ʾ���ַ���ת��Ϊ�޷��ŵ���ͨ�ַ���
 *			 ������洢��vecBytes��
 *			 ��ͬ�������غ���������ͬ�������ʹ��vector����ʾ��string
 *			 Ĭ����char(�з���)�洢�ģ���ʾ��ʵ�ʲ�һ����ʹ��vector
 *			 ����������ʾ����ʵ����һ�µ�
 * param: vecHexs: 16���Ʊ�ʾ���ַ���
 *		  vecHexsLen: ����С��vecHexs.size(),�����ܳ�����������Ϊż��
 * return: None
*/
void MyHEX_BYTES(const vector<unsigned char>& vecHexs, int vecHexsLen, vector<unsigned char>& vecBytes);

/**
 * function: ��16�����ַ���ʾ���ַ���ת��Ϊ�޷��ŵ���ͨ�ַ���
 * param: lpszHexs:ʮ�����Ʊ�ʾ���ַ���, nLen:ʮ�������ַ����ĳ���
 *		  lpszBytes:�洢���
 * return: None
*/
void MyHEX_BYTES(const unsigned char *lpszHexs, const int nLen, unsigned char *lpszBytes);

/**
 * function: ����ͨ�ַ���ת��Ϊ��16���Ʊ�ʾ���ַ���
 * param: strBytes����ͨ�ַ���
 *		  nByteLen������С��strBytes.size(),�����ܳ�����
 *		  strHexs���洢���
 * return: None
*/
void MyBYTES_HEX(const string& strBytes, int nByteLen, string& strHexs);

/**
 * function: ����ͨ�ַ���ת��Ϊ��16���Ʊ�ʾ���ַ���
 * param: strBytes����ͨ�ַ���
 *		  nByteLen������С��strBytes.size(),�����ܳ�����
 *		  strHexs���洢���
 * return: None
*/
void MyBYTES_HEX(const ucstring& strBytes, int nByteLen, ucstring& strHexs);

/**
 * function: ����ͨ�ַ���ת��Ϊ��16���Ʊ�ʾ���ַ���
 * param: vecBytes����ͨ�ַ���
 *		  nByteLen������С��vecBytes.size(),�����ܳ�����
 *		  vecHexs���洢���
 * return: None
*/
void MyBYTES_HEX(const vector<unsigned char>& vecBytes, int nByteLen, vector<unsigned char>& vecHexs);

/**
 * function: ����ͨ�ַ���ת��Ϊ��16���Ʊ�ʾ���ַ���
 * param: lpszBytes:��ͨ�ַ���,nLen:��ͨ�ַ����ĳ���,lpszHexs:װ�����16�����ַ���
 * return: None
*/
void MyBYTES_HEX(const unsigned char *lpszBytes, const int nLen, unsigned char *lpszHexs);

/**
 * function: ������ʮ�������ַ�װ���ɶ�Ӧ�Ķ������ַ���
 * param: ch:����ʮ�������ַ�
 * return: ��Ӧ�Ķ������ַ���
*/
string MyHexCharToBinary(const char& ch);

/**
 * function: ��ʮ�������ַ���װ���ɶ�Ӧ�Ķ������ַ���
 * param: strHex:ʮ�������ַ���
 * return: ��Ӧ�Ķ������ַ���
*/
string MyHexStrToBinary(const string& strHex);

/**
 * function: ��������Ӧ�Ķ������ַ������������
 * param: str1:��һ���������ַ���
 *		  str2:�ڶ����������ַ���
 *		  len:���ȣ������ַ����ȳ�
 *		  strOut:������
 * return: None
*/
void MyXOR(const string& str1, const string& str2, int len, string& strOut);

/**
 * function: ���������ַ���װ���ɶ�Ӧ��ʮ�������ַ���
 * param: strBin:�������ַ��������ȱ���Ϊ4�ı���
 * return: ��Ӧ��ʮ�������ַ���
*/
string MyBinaryStrToHex(const string& strBin);

/**
 * function: ������Ϊ4�Ķ������ַ���װ��Ϊ������Ӧ��ʮ�������ַ�
 * param: str:���ȱ���Ϊ4
 * return: ��Ӧ�ĵ����ַ�
*/
char MyBinary4ToHex(const string& str);

#endif  //__FUNC_H__