
// ���ܳ���(Ҫ�󣺰���#��������ֶ��ַ����е���ĸ������λ���ܣ����ֱ���ԭ�����ļ��������
// ��ʽ��#��������ֲ�����25)
// �������룺aBc4324#1
// ���������bCd4324#1
// ע��a:65 A:97 z:122 Z:90 ���ַ�(char����ʾ��Χ��-128~+127

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

const int size = 100;

int test_move()
{
	ifstream input;
	ofstream output;

	output.open("encry.txt");
	input.open("jiami.txt");

	char str1[size] = {0};
	int num = 0;

	while (!input.eof())
		input >> str1;

	int i = 0;
	while (str1[i] != '#')
		i++;

	int x = 0, y = 0;
	x = int(str1[i + 1]) - '0';
	if (str1[i + 2])
	{
		y = int(str1[i + 2]) - '0';
		num = x * 10 + y;
	}
	else
		num = x;

	if (num < 1 || num > 25)
		cout << "��λ���ֲ��Ϸ�" << endl;
	i = 0;

	// ���ܹ���
	while (str1[i] && str1[i] != '\0' && str1[i] != '\n')
	{
		if (isalnum(str1[i]))
		{
			if (str1[i] >= '0' && str1[i] <= '9')
				output << int(str1[i]) - 48;
			else if (str1[i] >= 'a' && str1[i] <= 'z')
			{
				// ���Ǵ���122(z),�Լ�����127�������ȡ����
				if (int(str1[i] > 122 - num))
				{
					str1[i] -= 26;		// Ϊ�˷�ֹ������ȼ�26���ڼ�num
					str1[i] += num;
				}
				else
					str1[i] = str1[i] + num;
				output << str1[i];
			}
			else if (str1[i] >= 'A' && str1[i] <= 'Z')
			{
				str1[i] += num;
				if (int(str1[i]) > 90)
					str1[i] -= 26;
				output << str1[i];
			}
			//else
			//{
			//	cout << "������ַ������Ϸ�" << endl;
			//	break;
			//}
		}
		else
			output << str1[i];
		i++;
	}

	input.close();
	output.close();

	system("pause");
	return 0;
}

