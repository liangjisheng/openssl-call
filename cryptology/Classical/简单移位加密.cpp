
// 加密程序(要求：按照#后面的数字对字符串中的字母进行移位加密，数字保持原样，文件输入输出
// 方式，#后面的数字不超过25)
// 样例输入：aBc4324#1
// 样例输出：bCd4324#1
// 注：a:65 A:97 z:122 Z:90 ，字符(char）表示范围：-128~+127

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
		cout << "移位数字不合法" << endl;
	i = 0;

	// 加密过程
	while (str1[i] && str1[i] != '\0' && str1[i] != '\n')
	{
		if (isalnum(str1[i]))
		{
			if (str1[i] >= '0' && str1[i] <= '9')
				output << int(str1[i]) - 48;
			else if (str1[i] >= 'a' && str1[i] <= 'z')
			{
				// 考虑大于122(z),以及超过127的情况，取并集
				if (int(str1[i] > 122 - num))
				{
					str1[i] -= 26;		// 为了防止溢出，先减26，在加num
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
			//	cout << "输入的字符串不合法" << endl;
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

