
/**
 * function: 奇偶校验
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
 * function: v中1的个数为奇数返回true，否则返回false
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
		// 每次执行完这句话，uTmp最左边的1就会变为0，而其它位不变
		uTmp = uTmp & (uTmp - 1);
	}

	return bParity;
}
