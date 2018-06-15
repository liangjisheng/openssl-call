
// һ������������^(���)ͬ���������õ����������

#include <iostream>
#include <string.h>

using std::cout;
using std::endl;

/**
 * function: ���ܽ����ַ���������ʱlpszReturn����ΪNULL,����ʱlpszTextΪ
 *			 ���ģ�lpszReturnΪ���ģ�lpszKeyΪ��Կ
 * param: lpszText��ռ���ڴ�����ʵ�ʵĴ�С��3���ֽڣ���������Զ��������
 * return: 
*/
void EncodeString(const char* lpszText, char** lpszReturn, const char* lpszKey)
{
	int nTextLen = 0;
	char *cPos = NULL;
	char *pDest = NULL;

	if (!lpszReturn)		// ����
	{
		nTextLen = strlen(lpszText);
		pDest = (char *)lpszText;
	}
	else					// ����
	{
		// �����Զ������ֹ���
		cPos = (char *)lpszText;
		while (true)
		{
			if (*cPos == '=' && cPos[1] == '=' && cPos[2] == '\0')
				break;
			cPos++;
		}
		if (!cPos)		// û���ҵ���������Ҳ���Ǽ���
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
	EncodeString(strText, NULL, "Zimmerk");		// ����
	cout<< strText << endl;
	cout << "===============================================================" << endl;
	EncodeString(strText, &lpszDest, "Zimmerk");	// ����
	if (lpszDest && *lpszDest)
	{
		cout << lpszDest << endl;
		delete [] lpszDest;
	}
	else
		cout << "NULL" << endl;
}

