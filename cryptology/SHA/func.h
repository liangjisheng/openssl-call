
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
 * function: 将一个16进制表示的字符转换为对应的整数
 * param: c: 16进制表示的字符, d:表示结果的整数
 * return: None
*/
void My16cTo10(unsigned char c,unsigned int &d);

/**
 * function: 将一个整数表示为对应的16进制字符
 * param: d: 整数，c:16进制字符
 * return: None
*/
void My10To16(unsigned int d, unsigned char& c);

/**
 * function: 将16进制字符表示的字符串转换为无符号的普通字符串
 *			 将结果存储到strBytes中
 * param: strHexs: 16进制表示的字符串
 *		  strHexLen: 可以小于strHexs.size(),但不能超过它，必须为偶数
 * return: None
*/
void MyHEX_BYTES(const string& strHexs, int strHexLen, string& strBytes);

/**
 * function: 将16进制字符表示的字符串转换为无符号的普通字符串
 *			 将结果存储到strBytes中
 * param: strHexs: 16进制表示的字符串
 *		  strHexLen: 可以小于strHexs.size(),但不能超过它，必须为偶数
 * return: None
*/
void MyHEX_BYTES(const ucstring& strHexs, int strHexLen, ucstring& strBytes);

/**
 * function: 将16进制字符表示的字符串转换为无符号的普通字符串
 *			 将结果存储到vecBytes中
 *			 与同名的重载函数作用相同，但这个使用vector来显示，string
 *			 默认是char(有符号)存储的，显示与实际不一样，使用vector
 *			 可以做到显示的与实际是一致的
 * param: vecHexs: 16进制表示的字符串
 *		  vecHexsLen: 可以小于vecHexs.size(),但不能超过它，必须为偶数
 * return: None
*/
void MyHEX_BYTES(const vector<unsigned char>& vecHexs, int vecHexsLen, vector<unsigned char>& vecBytes);

/**
 * function: 将16进制字符表示的字符串转换为无符号的普通字符串
 * param: lpszHexs:十六进制表示的字符串, nLen:十六进制字符串的长度
 *		  lpszBytes:存储结果
 * return: None
*/
void MyHEX_BYTES(const unsigned char *lpszHexs, const int nLen, unsigned char *lpszBytes);

/**
 * function: 将普通字符串转换为用16进制表示的字符串
 * param: strBytes：普通字符串
 *		  nByteLen：可以小于strBytes.size(),但不能超过它
 *		  strHexs：存储结果
 * return: None
*/
void MyBYTES_HEX(const string& strBytes, int nByteLen, string& strHexs);

/**
 * function: 将普通字符串转换为用16进制表示的字符串
 * param: strBytes：普通字符串
 *		  nByteLen：可以小于strBytes.size(),但不能超过它
 *		  strHexs：存储结果
 * return: None
*/
void MyBYTES_HEX(const ucstring& strBytes, int nByteLen, ucstring& strHexs);

/**
 * function: 将普通字符串转换为用16进制表示的字符串
 * param: vecBytes：普通字符串
 *		  nByteLen：可以小于vecBytes.size(),但不能超过它
 *		  vecHexs：存储结果
 * return: None
*/
void MyBYTES_HEX(const vector<unsigned char>& vecBytes, int nByteLen, vector<unsigned char>& vecHexs);

/**
 * function: 将普通字符串转换为用16进制表示的字符串
 * param: lpszBytes:普通字符串,nLen:普通字符串的长度,lpszHexs:装换后的16进制字符串
 * return: None
*/
void MyBYTES_HEX(const unsigned char *lpszBytes, const int nLen, unsigned char *lpszHexs);

/**
 * function: 将单个十六进制字符装换成对应的二进制字符串
 * param: ch:单个十六进制字符
 * return: 对应的二进制字符串
*/
string MyHexCharToBinary(const char& ch);

/**
 * function: 将十六进制字符串装换成对应的二进制字符串
 * param: strHex:十六进制字符串
 * return: 对应的二进制字符串
*/
string MyHexStrToBinary(const string& strHex);

/**
 * function: 将两个对应的二进制字符串做异或运算
 * param: str1:第一个二进制字符串
 *		  str2:第二个二进制字符串
 *		  len:长度，两个字符串等长
 *		  strOut:运算结果
 * return: None
*/
void MyXOR(const string& str1, const string& str2, int len, string& strOut);

/**
 * function: 将二进制字符串装换成对应的十六进制字符串
 * param: strBin:二进制字符串，长度必须为4的倍数
 * return: 对应的十六进制字符串
*/
string MyBinaryStrToHex(const string& strBin);

/**
 * function: 将长度为4的二进制字符串装换为单个对应的十六进制字符
 * param: str:长度必须为4
 * return: 对应的单个字符
*/
char MyBinary4ToHex(const string& str);

#endif  //__FUNC_H__