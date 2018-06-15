
#include "func.h"

void My16cTo10(unsigned char chHex, unsigned int &nDec)
{
	if (!isalnum(chHex))
		return ;

	if ('A'== chHex || 'a'== chHex)
		nDec = 10;
	else if ('B' == chHex || 'b' == chHex)
		nDec = 11;
	else if ('C' == chHex || 'c' == chHex)
		nDec = 12;
	else if ('D' == chHex || 'd' == chHex)
		nDec = 13;
	else if ('E' == chHex || 'e' == chHex)
		nDec = 14;
	else if ('F' == chHex || 'f' == chHex)
		nDec = 15;
	else if (chHex >= '0' && chHex <= '9')
		nDec = chHex - '0';
	else
		return;
}

void My10To16(unsigned int d, unsigned char& c)
{
	if (d < 0 || d > 15)
		return ;

	if (d >= 0 && d <= 9)
		c = '0' + d;
	else if (d >= 10 && d <= 15)
		c = 'a' + d - 10;
}

void MyHEX_BYTES(const string& strHexs, int strHexLen, string& strBytes)
{
	vector<unsigned char> vecHexs;
	copy(strHexs.begin(), strHexs.end(), back_inserter(vecHexs));
	vector<unsigned char> vecBytes;

	// 必须传入偶数位16进制字符
	if (strHexLen % 2)
		return;

	for (int i = 0; i < strHexLen; i += 2)
	{
		unsigned int uiHigher = 0, uiLower = 0;
		My16cTo10(vecHexs[i], uiHigher);
		//uiHigher = atoi(&strHex[i]);
		uiHigher <<= 4;
		// uiLower = atoi(&strHex[i + 1]);
		My16cTo10(vecHexs[i + 1], uiLower);
		vecBytes.push_back((uiHigher | uiLower));
	}
	strBytes = "";
	copy(vecBytes.begin(), vecBytes.end(), back_inserter(strBytes));
}

void MyHEX_BYTES(const vector<unsigned char>& vecHexs, int vecHexsLen, vector<unsigned char>& vecBytes)
{
	// 必须传入偶数位16进制字符
	if (vecHexsLen % 2)
		return;

	vector<unsigned char>().swap(vecBytes);
	for (int i = 0; i < vecHexsLen; i += 2)
	{
		unsigned int uiHigher = 0, uiLower = 0;
		My16cTo10(vecHexs[i], uiHigher);
		//uiHigher = atoi(&strHex[i]);
		uiHigher <<= 4;
		// uiLower = atoi(&strHex[i + 1]);
		My16cTo10(vecHexs[i + 1], uiLower);
		vecBytes.push_back((uiHigher | uiLower));
	}
}

void MyHEX_BYTES(const unsigned char *lpszHexs, const int nLen, unsigned char *lpszBytes)
{
	char *lpszDataHexs = (char *)malloc(nLen + 1);
	memset(lpszDataHexs, 0, nLen + 1);
	memcpy(lpszDataHexs, lpszHexs, nLen);

	string strHexs(lpszDataHexs);
	string strBytes;
	MyHEX_BYTES(strHexs, nLen, strBytes);

	memcpy(lpszBytes, strBytes.c_str(), strBytes.size());

	if (lpszDataHexs)
	{
		free(lpszDataHexs);
		lpszDataHexs = NULL;
	}
}

void MyBYTES_HEX(const string& strBytes, int nByteLen, string& strHexs)
{
	strHexs = "";
	vector<unsigned char> vecBytes;
	copy(strBytes.begin(), strBytes.end(), back_inserter(vecBytes));
	// vector<unsigned char> vecHexs;
	unsigned char szHexTemp[3] = {0};

	for (int i = 0; i < nByteLen; ++i)
	{
		memset(szHexTemp, 0, sizeof(szHexTemp));
		unsigned char ch = ' ';
		My10To16(vecBytes[i] >> 4, szHexTemp[0]);
		My10To16(vecBytes[i] & 0xf, szHexTemp[1]);
		// itoa(nTemp, (char*)szHexTemp, 16);
		strHexs.push_back(szHexTemp[0]);
		strHexs.push_back(szHexTemp[1]);
	}
}

void MyHEX_BYTES(const ucstring& strHexs, int strHexLen, ucstring& strBytes)
{
	// 必须传入偶数位16进制字符
	if (strHexLen % 2)
		return;

	for (int i = 0; i < strHexLen; i += 2)
	{
		unsigned int uiHigher = 0, uiLower = 0;
		My16cTo10(strHexs[i], uiHigher);
		//uiHigher = atoi(&strHex[i]);
		uiHigher <<= 4;
		// uiLower = atoi(&strHex[i + 1]);
		My16cTo10(strHexs[i + 1], uiLower);
		strBytes.push_back((uiHigher | uiLower));
	}

}

void MyBYTES_HEX(const ucstring& strBytes, int nByteLen, ucstring& strHexs)
{
	unsigned char szHexTemp[3] = {0};
	for (int i = 0; i < nByteLen; ++i)
	{
		memset(szHexTemp, 0, sizeof(szHexTemp));
		unsigned char ch = ' ';
		My10To16(strBytes[i] >> 4, szHexTemp[0]);
		My10To16(strBytes[i] & 0xf, szHexTemp[1]);
		// itoa(nTemp, (char*)szHexTemp, 16);
		strHexs.push_back(szHexTemp[0]);
		strHexs.push_back(szHexTemp[1]);
	}
}

void MyBYTES_HEX(const vector<unsigned char>& vecBytes, int nByteLen, vector<unsigned char>& vecHexs)
{
	vector<unsigned char>().swap(vecHexs);
	unsigned char szHexTemp[3] = {0};
	for (int i = 0; i < nByteLen; ++i)
	{
		memset(szHexTemp, 0, sizeof(szHexTemp));
		unsigned char ch = ' ';
		My10To16(vecBytes[i] >> 4, szHexTemp[0]);
		My10To16(vecBytes[i] & 0xf, szHexTemp[1]);
		// itoa(nTemp, (char*)szHexTemp, 16);
		vecHexs.push_back(szHexTemp[0]);
		vecHexs.push_back(szHexTemp[1]);
	}
}

void MyBYTES_HEX(const unsigned char *lpszBytes, const int nLen, unsigned char *lpszHexs)
{
	vector<unsigned char> vecBytes;
	for (int i = 0; i < nLen; ++i)
		vecBytes.push_back(lpszBytes[i]);

	vector<unsigned char> vecHexs;
	MyBYTES_HEX(vecBytes, vecBytes.size(), vecHexs);

	for (size_t i = 0; i < vecHexs.size(); ++i)
		lpszHexs[i] = vecHexs[i];

	//char *lpszDataBytes = (char *)malloc(nLen + 1);
	//memset(lpszDataBytes, 0, nLen + 1);
	//memcpy(lpszDataBytes, lpszBytes, nLen);

	//string strBytes(lpszDataBytes);
	//string strHexs;
	//MyBYTES_HEX(strBytes, nLen, strHexs);
	//memcpy(lpszHexs, strHexs.c_str(), strHexs.size());

	//if (lpszDataBytes)
	//{
	//	free(lpszDataBytes);
	//	lpszDataBytes = NULL;
	//}
}

string MyHexCharToBinary(const char& ch)
{
	switch(ch)
	{
	case '0':
		return "0000";
	case '1':
		return "0001";
	case '2':
		return "0010";
	case '3':
		return "0011";
	case '4':
		return "0100";
	case '5':
		return "0101";
	case '6':
		return "0110";
	case '7':
		return "0111";
	case '8':
		return "1000";
	case '9':
		return "1001";
	case 'a':
		return "1010";
	case 'b':
		return "1011";
	case 'c':
		return "1100";
	case 'd':
		return "1101";
	case 'e':
		return "1110";
	case 'f':
		return "1111";
	case 'A':
		return "1010";
	case 'B':
		return "1011";
	case 'C':
		return "1100";
	case 'D':
		return "1101";
	case 'E':
		return "1110";
	case 'F':
		return "1111";
	default:
		return "";
	}
}

string MyHexStrToBinary(const string& strHex)
{
	string strRes("");
	for (string::size_type i=0; i < strHex.size(); ++i)
		strRes += MyHexCharToBinary(strHex[i]);
	return strRes;
}

void MyXOR(const string& str1, const string& str2, int len, string& strOut)
{
	strOut = "";
	for (int i = 0; i < len; ++i)
	{
		char ch = str1[i] ^ str2[i];
		if (ch == 1)
			strOut.push_back('1');
		else
			strOut.push_back('0');
	}
}

char MyBinary4ToHex(const string& str)
{
	if (str == "")
		return '0';

	if (str == "0000")
		return '0';
	else if (str == "0001")
		return '1';
	else if (str == "0010")
		return '2';
	else if (str == "0011")
		return '3';
	else if (str == "0100")
		return '4';
	else if (str == "0101")
		return '5';
	else if (str == "0110")
		return '6';
	else if (str == "0111")
		return '7';
	else if (str == "1000")
		return '8';
	else if (str == "1001")
		return '9';
	else if (str == "1010")
		return 'A';
	else if (str == "1011")
		return 'B';
	else if (str == "1100")
		return 'C';
	else if (str == "1101")
		return 'D';
	else if (str == "1110")
		return 'E';
	else if (str == "1111")
		return 'F';
	else
		return '0';
}

string MyBinaryStrToHex(const string& strBin)
{
	if (strBin.size() % 4)
		return "";

	string strHex("");
	for (string::size_type i = 0; i < strBin.size(); i += 4)
		strHex += MyBinary4ToHex(strBin.substr(i, 4));
	return strHex;
}
