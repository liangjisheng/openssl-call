
#include <stdio.h>

// 通过嵌套宏定义，制作一张包括0~255各个数字中包含1的个数，其中包含偶数个1，
// 则ParityTable256[i]=0，否则ParityTable256[i]=1
static const bool ParityTable256[256] =
{
#define P2(n) n, n^1, n^1, n
#define P4(n) P2(n), P2(n^1), P2(n^1), P2(n)
#define P6(n) P4(n), P4(n^1), P4(n^1), P4(n)
	P6(0), P6(1), P6(1), P6(0)
};

void PrintParityTable()
{
	for (int i = 0; i < sizeof(ParityTable256); ++i)
	{
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%d ", ParityTable256[i]);
	}
	printf("\n");
}

bool CheckSum_2(unsigned char ch)
{
	return ParityTable256[ch];
}

bool CheckSum_2(unsigned int num)
{
	// 1.通过v^=v>>16，将v中的低16位与高16位进行按位或（^）操作
	//相当于0~16位保留1的总个数的奇偶与v中的1的总  个数的奇偶相同
	// 2.通过v^=v>>8,将v中的9~16位与0~8位进行按位或（^）操作
	// 相当于0~8位保留1的总个数的奇偶与0~16中1的总个数的奇偶相同
	// 3.通过1, 2操作，最初v中1的总个数的奇偶与最后v中1~8位中1的
	// 总个数的奇偶相同，v&0xff相当于获取v中1~8比特位的1，然后再查表即可
	unsigned int v = num;
	v ^= v >> 16;
	v ^= v >> 8;
	return ParityTable256[v & 0xff];

	// 或者可以通过下面两行代码实现上面同样的功能
	// unsigned char *p = (unsigned char *) &num;
	// return ParityTable256[p[0] ^p[1] ^ p[2] ^ p[3]];
}
