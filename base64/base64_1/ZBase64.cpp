
#include "ZBase64.h"

string ZBase64::Encode(const unsigned char* data, int nDataByte)
{
	// ��������������õ������Ŀɴ�ӡ�ַ�
	const char EncodeTable[] = 
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	string strEncode = "";
	unsigned char Tmp[4] = {0};
	int LineLength = 0;

	for(int i = 0; i < nDataByte / 3; i++)
	{
		Tmp[1] = *data++;
		Tmp[2] = *data++;
		Tmp[3] = *data++;
		strEncode += EncodeTable[Tmp[1] >> 2];
		strEncode += EncodeTable[((Tmp[1] << 4) | (Tmp[2] >> 4)) & 0x3f];
		strEncode += EncodeTable[((Tmp[2] << 2) | (Tmp[3] >> 6)) & 0x3f];
		strEncode += EncodeTable[Tmp[3] & 0x3f];

		// ÿ����76���ַ�������һ�Σ���׼�涨
		if(LineLength += 4, LineLength == 76) 
		{
			strEncode += "\r\n"; 
			LineLength = 0;
		}

		// ���������ݽ��б��룬�ֽ�������3�ı���
		int nMod = nDataByte % 3;
		if(1 == nMod)
		{
			Tmp[1] = *data++;
			strEncode += EncodeTable[(Tmp[1] & 0xfc) >> 2];
			strEncode += EncodeTable[(Tmp[1] & 0x03) << 4];
			strEncode += "==";
		}
		else if(2 == nMod)
		{
			Tmp[1] = *data++;
			Tmp[2] = *data++;
			strEncode += EncodeTable[(Tmp[1] & 0xfc) >> 2];
			strEncode += EncodeTable[((Tmp[1] & 0x03) << 4) | ((Tmp[2] & 0xf0) >> 4)];
			strEncode += EncodeTable[(Tmp[2] & 0x0f) << 2];
			strEncode += "=";
		}
	}

	return strEncode;
}


string ZBase64::Decode(const char* data, int nDataByte, int &nOutByte)
{
	// ������Ա����Ŀɴ�ӡ�ַ���ASCII��ֵ��Ϊ���������
	// ����ڱ�����еı����ַ���Ӧ�ı��������ֵ
	const char DecodeTable[] = 
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		62,		// '+' ASCIIֵΪ43
		0, 0, 0,
		63,		// '/' ASCIIֵΪ47
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61,		// '0'-'9' ASCIIֵ��48-57
		0, 0, 0, 0, 0, 0, 0,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,		// 'A'-'Z'	ASCIIֵ��65-90
		0, 0, 0, 0, 0, 0,
		26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51		// 'a'-'z' ASCIIֵ��97-122
	};

	string strDecode = "";
	int nValue = 0;
	int i = 0;
	while(i < nDataByte)
	{
		if(*data != '\r' && *data != '\n')
		{
			nValue = DecodeTable[*data++] << 18;
			nValue += DecodeTable[*data++] << 12;
			strDecode += (nValue & 0x00ff0000) >> 16;
			nOutByte++;
			if(*data != '=')
			{
				nValue += DecodeTable[*data++] << 6;
				strDecode += (nValue & 0x0000ff00) >> 8;
				nOutByte++;
				if(*data != '=')
				{
					nValue += DecodeTable[*data++];
					strDecode += nValue & 0x000000ff;
					nOutByte++;
				}
			}
			i += 4;	// ÿ4��base64λ�ַ���������ַ���3���ֽ�
		}
		else		// �س����У�����
		{
			data++;
			i++;
		}
	}
	return strDecode;
}

