
// 一个数连续两次^(异或)同样的数，得到这个数本身

#include <iostream>
#include <string.h>

using std::cout;
using std::endl;

/**
 * function: 加密解密字符串，加密时lpszReturn设置为NULL,解密时lpszText为
 *			 密文，lpszReturn为明文，lpszKey为密钥
 * param: lpszText所占的内存必须比实际的大小大3个字节，用来存放自定义结束符
 * return: 
*/
void EncodeString(const char* lpszText, char** lpszReturn, const char* lpszKey)
{
	int nTextLen = 0;
	char *cPos = NULL;
	char *pDest = NULL;

	if (!lpszReturn)		// 加密
	{
		nTextLen = strlen(lpszText);
		pDest = (char *)lpszText;
	}
	else					// 解密
	{
		// 查找自定义的终止标记
		cPos = (char *)lpszText;
		while (true)
		{
			if (*cPos == '=' && cPos[1] == '=' && cPos[2] == '\0')
				break;
			cPos++;
		}
		if (!cPos)		// 没有找到结束符，也不是加密
			return ;
		nTextLen = cPos - lpszText;
		pDest = new char[nTextLen + 3];	// ==\0
		memset(pDest, 0, nTextLen + 3);
	}

	int nKeyLen = strlen(lpszKey);
	int i = 0;
	int k = 0;
	for (; i < nTextLen; ++i)
	{
		pDest[i] = lpszText[i] ^ lpszKey[k];
		k++;
		if (k >= nKeyLen)
			k = 0;
	}

	if (!cPos)
		memcpy(pDest + nTextLen, "==\0", 3);
	else
	{
		memset(pDest + nTextLen, 0, 1);
		*lpszReturn = pDest;
	}
}

void test_trans()
{
	char strText[128] = "Hello world! I'm zimmerk. I'm a boy. What's your name?";
	char *lpszDest = NULL;
	cout << strText << endl;
	cout << "===============================================================" << endl;
	EncodeString(strText, NULL, "Zimmerk");		// 加密
	cout<< strText << endl;
	cout << "===============================================================" << endl;
	EncodeString(strText, &lpszDest, "Zimmerk");	// 解密
	if (lpszDest && *lpszDest)
	{
		cout << lpszDest << endl;
		delete [] lpszDest;
	}
	else
		cout << "NULL" << endl;
}

