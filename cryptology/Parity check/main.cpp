
#include <stdio.h>

bool CheckNum(const unsigned int v);
void PrintParityTable();
bool CheckSum_2(unsigned char ch);
bool CheckSum_2(unsigned int num);

int main()
{
	PrintParityTable();
	printf("\n");

	unsigned char ch = '0';
	printf("%d\n", CheckSum_2(ch));
	ch = '1';
	printf("%d\n", CheckSum_2(ch));

	unsigned int num = 3;
	printf("%d\n", CheckSum_2(num));
	num = 4;
	printf("%d\n", CheckSum_2(num));

	getchar();
	return 0;
}
