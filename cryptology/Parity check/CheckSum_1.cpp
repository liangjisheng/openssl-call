
/**
 * function: ��żУ��
 * param:
 * return: 
*/
bool CheckSum_1(char *lpszData, int length, char sum, bool mode)
{
	char tmp = 0;
	for (int i = 0; i < length; ++i)
	{
		tmp += *lpszData;
		lpszData++;
	}

	if (mode)
	{
		if (tmp + sum == 1)
			return true;
		else
			return false;
	}
	else
	{
		if (tmp + sum == 0)
			return true;
		else
			return false;
	}
}


/**
 * function: v��1�ĸ���Ϊ��������true�����򷵻�false
 * param:
 * return: 
*/
bool CheckNum(const unsigned int v)
{
	bool bParity = false;
	unsigned int uTmp = v;
	while (uTmp)
	{
		bParity = !bParity;
		// ÿ��ִ������仰��uTmp����ߵ�1�ͻ��Ϊ0��������λ����
		uTmp = uTmp & (uTmp - 1);
	}

	return bParity;
}
