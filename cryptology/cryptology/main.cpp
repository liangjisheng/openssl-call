
#include "func.h"
#include "mySha1.h"
#include "myDES.h"
#include "TDES.h"

void PACE();

void BAC();

string Decrypt(const string& strCipherHexs, const string& strKeyHexs);

string Encrypt(const string& strPlaintextHexs, const string& strKeyHexs);

void test()
{
	vector<unsigned char> vecBytes;
	for (int i = 0; i < 256; ++i)
		vecBytes.push_back(i);

	vector<unsigned char> vecHexs;
	MyBYTES_HEX(vecBytes, vecBytes.size(), vecHexs);

	vector<unsigned char> vecBytes1;
	MyHEX_BYTES(vecHexs, vecHexs.size(), vecBytes1);


	string strHexs;
	copy(vecHexs.begin(), vecHexs.end(), back_inserter(strHexs));

	string strBytes;
	MyHEX_BYTES(strHexs, strHexs.size(), strBytes);

	string strHexs1;
	MyBYTES_HEX(strBytes, strBytes.size(), strHexs1);	
}

void test1()
{
	ucstring strBytes, strHexs, strBytes1;
	for (int i = 0; i < 256; ++i)
		strBytes.push_back(i);
	cout << strBytes << endl;

	MyBYTES_HEX(strBytes, strBytes.size(), strHexs);
	cout << strHexs << endl;
	MyHEX_BYTES(strHexs, strHexs.size(), strBytes1);
	cout << strBytes1 << endl;
}

void test_Decrypt_Encrypt()
{
	// szKpi = 0x004fcbac "89ded1b26624ec1e634c1989302849dd"
	string strKpi("89ded1b26624ec1e634c1989302849dd");

	// 密文 "95a3a016522ee98d01e76cb6b98b42c3"
	// unsigned char szICRandom_E[] = "95a3a016522ee98d01e76cb6b98b42c3";
	// string strICRandom_E("95a3a016522ee98d01e76cb6b98b42c3");

	// 明文 "16058ed237e82c1e15710dd8cceb9a81"
	// string strICRandom_P = Decrypt(strICRandom_E, strKpi);


	string strICRandom_P("16058ed237e82c1e15710dd8cceb9a81");
	string strICRandom_E1 = Encrypt(strICRandom_P, strKpi);
}

int KDF(const string& strKseed, const char& ch, char *lpszOut)
{
	// 检查参数合法性
	if (strKseed == "")
		return -1;
	if (ch != '1' && ch != '2' && ch != '3')
		return -2;
	if (NULL == lpszOut)
		return -3;

	// 在末尾追加数据
	string strKseedTmp(strKseed);
	for (int i = 0; i < 7; ++i)
		strKseedTmp.push_back('0');
	strKseedTmp.push_back(ch);

	string strKseedBytes("");
	MyHEX_BYTES(strKseedTmp, strKseedTmp.size(), strKseedBytes);

	// 计算strKseedBytes的哈希
	mySHA1 sha1;
	char szSha1[65] = {0};
	sha1.SHA_GO(strKseedBytes.c_str(), strKseedBytes.size(), szSha1);
	memcpy(lpszOut, szSha1, 32);

	return 0;
}

int main()
{
	//PACE();
	//BAC();
	//test1();
	//test_Decrypt_Encrypt();

	mySHA1 sha1;
	char szSha1[65] = {0};
	string strMRZ("116289377289030822202118");
	sha1.SHA_GO(strMRZ.c_str(), strMRZ.size(), szSha1);
	string strKseed(szSha1, szSha1 + 32);
	char szSEnc[65] = {0};
	KDF(strKseed, '1', szSEnc);
	printf("KSEnc: %s\n", szSEnc);
	char szSMac[65] = {0};
	KDF(strKseed, '2', szSMac);
	printf("KSMac: %s\n", szSMac);

	system("pause");
	return 0;
}

void PACE()
{
	mySHA1 sha1;
	string strMrz = "T22000129364081251010318";
	// string strMrz = "SE9003768585031051506130";
	// string strMrz = "L898902C<369080619406236";

	string strMrzSha1 = "";
	char szMrzSha1[50] = {0};
	sha1.SHA_GO(strMrz.c_str(), strMrz.size(), szMrzSha1);
	int i = 0;
	while (szMrzSha1[i])
	{
		strMrzSha1.push_back(szMrzSha1[i]);
		i++;
	}

	// string strHexs = strMrzSha1.substr(0, 32);
	string strHexs = strMrzSha1;
	for (int i = 0; i < 7; ++i)
		strHexs.push_back('0');
	strHexs.push_back('1');

	string strBytes;
	MyHEX_BYTES(strHexs, strHexs.size(), strBytes);

	char szSha1[50] = {0};
	sha1.SHA_GO(strBytes.c_str(), strBytes.size(), szSha1);

	string strKpi = "";
	for (int i = 0; i < 32; ++i)
		strKpi.push_back(szSha1[i]);
}

void BAC()
{
	mySHA1 sha1;
	// string strMrz = "T22000129364081251010318";
	// string strMrz = "SE9003768585031051506130";
	string strMrz = "L898902C<369080619406236";

	string strMrzSha1 = "";
	char szMrzSha1[50] = {0};
	sha1.SHA_GO(strMrz.c_str(), strMrz.size(), szMrzSha1);
	int i = 0;
	while (szMrzSha1[i])
	{
		strMrzSha1.push_back(szMrzSha1[i]);
		i++;
	}

	strMrzSha1 = strMrzSha1.substr(0, 32);

	// string strHexs = strMrzSha1.substr(0, 32);
	string strHexs = strMrzSha1;
	for (int i = 0; i < 7; ++i)
		strHexs.push_back((char)0);
	strHexs.push_back(char(1));

	string strBytes;
	MyHEX_BYTES(strHexs, strHexs.size(), strBytes);

	char szSha1[50] = {0};
	sha1.SHA_GO(strBytes.c_str(), strBytes.size(), szSha1);

	string strKpi = "";
	for (int i = 0; i < 32; ++i)
		strKpi.push_back(szSha1[i]);
}

string Decrypt(const string& strCipherHexs, const string& strKeyHexs)
{
	if (strCipherHexs.size() % 16 != 0 || strKeyHexs.size() != 32)
		return "";

	TDES des3;
	string strBinBegin = MyHexStrToBinary(strCipherHexs.substr(0, 16));
	string strResHex;
	string strKeyBytes;
	MyHEX_BYTES(strKeyHexs, strKeyHexs.size(), strKeyBytes);

	//string strCipher8Bytes;
	//MyHEX_BYTES(strCipher.substr(0, 16), 16, strCipher8Bytes);
	//string strOutByte;
	//unsigned char ucOut[8] = {0};
	//des3.des_3((unsigned char*)strCipher8Bytes.c_str(),(unsigned char*)strKeyBytes.c_str(), ucOut, 0);

	//string strOutBytes(ucOut, ucOut + sizeof(ucOut) / sizeof(ucOut[0]));
	//string strOutHex;
	//vector<unsigned char> vecOut(ucOut, ucOut + sizeof(ucOut) / sizeof(ucOut[0]));
	//vector<unsigned char> vecOutHex;
	//MyBYTES_HEX(strOutBytes, strOutBytes.size(), strOutHex);
	//strResHex = strOutHex;

	for (ucstring::size_type i = 0; i < strCipherHexs.size() / 16; ++i)
	{
		string strHexs = strCipherHexs.substr(i * 16, 16);
		//string strCipherBin = MyHexStrToBinary(strHexs);
		string strCipherBytes;
		MyHEX_BYTES(strHexs, strHexs.size(), strCipherBytes);

		unsigned char ucOut[8] = {0};
		des3.des_3((unsigned char*)strCipherBytes.c_str(), (unsigned char*)strKeyBytes.c_str(), ucOut, 0);

		vector<unsigned char> vecOut;
		vector<unsigned char> vecOutHex;
		copy(ucOut, ucOut + sizeof(ucOut) / sizeof(ucOut[0]), back_inserter(vecOut));
		MyBYTES_HEX(vecOut, vecOut.size(), vecOutHex);

		string strOutHex;
		copy(vecOutHex.begin(), vecOutHex.end(), back_inserter(strOutHex));

		// 异或操作, 头8个字节不做异或操作
		if (i != 0)
		{
			string strBin_P = MyHexStrToBinary(strOutHex);
			string strXor;
			MyXOR(strBinBegin, strBin_P, strBinBegin.size(), strXor);
			strOutHex = MyBinaryStrToHex(strXor);
		}

		strResHex += strOutHex;
	}

	return strResHex;
}

string Encrypt(const string& strPlaintextHexs, const string& strKeyHexs)
{
	if (strPlaintextHexs.size() % 16 != 0 || strKeyHexs.size() != 32)
		return "";

	TDES des3;
	string strResHex;
	string strBinBegin;

	string strKeyBytes;
	MyHEX_BYTES(strKeyHexs, strKeyHexs.size(), strKeyBytes);

	for (string::size_type i = 0; i < strPlaintextHexs.size() / 16; ++i)
	{
		string strBytes;
		string strHexs = strPlaintextHexs.substr(i * 16, 16);
		MyHEX_BYTES(strHexs, 16, strBytes);
		string strBin_P = MyHexStrToBinary(strHexs);

		// 异或操作, 头8个字节不做异或操作
		if (i != 0)
		{
			string strXor;
			MyXOR(strBinBegin, strBin_P, strBinBegin.size(), strXor);
			string strXorHex = MyBinaryStrToHex(strXor);
			MyHEX_BYTES(strXorHex, strXorHex.size(), strBytes);
		}

		unsigned char ucOut[8] = {0};
		des3.des_3((unsigned char*)strBytes.c_str(), (unsigned char*)strKeyBytes.c_str(), ucOut, 1);

		vector<unsigned char> vecOut;
		vector<unsigned char> vecOutHex;
		copy(ucOut, ucOut + sizeof(ucOut) / sizeof(ucOut[0]), back_inserter(vecOut));
		MyBYTES_HEX(vecOut, vecOut.size(), vecOutHex);

		string strOutHex;
		copy(vecOutHex.begin(), vecOutHex.end(), back_inserter(strOutHex));

		if (0 == i)
			strBinBegin = MyHexStrToBinary(strOutHex);

		strResHex += strOutHex;
	}

	return strResHex;
}
