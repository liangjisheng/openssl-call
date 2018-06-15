
#include <stdio.h>

// ͨ��Ƕ�׺궨�壬����һ�Ű���0~255���������а���1�ĸ��������а���ż����1��
// ��ParityTable256[i]=0������ParityTable256[i]=1
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
	// 1.ͨ��v^=v>>16����v�еĵ�16λ���16λ���а�λ��^������
	//�൱��0~16λ����1���ܸ�������ż��v�е�1����  ��������ż��ͬ
	// 2.ͨ��v^=v>>8,��v�е�9~16λ��0~8λ���а�λ��^������
	// �൱��0~8λ����1���ܸ�������ż��0~16��1���ܸ�������ż��ͬ
	// 3.ͨ��1, 2���������v��1���ܸ�������ż�����v��1~8λ��1��
	// �ܸ�������ż��ͬ��v&0xff�൱�ڻ�ȡv��1~8����λ��1��Ȼ���ٲ����
	unsigned int v = num;
	v ^= v >> 16;
	v ^= v >> 8;
	return ParityTable256[v & 0xff];

	// ���߿���ͨ���������д���ʵ������ͬ���Ĺ���
	// unsigned char *p = (unsigned char *) &num;
	// return ParityTable256[p[0] ^p[1] ^ p[2] ^ p[3]];
}
