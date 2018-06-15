
// ��һ�����ݽ���������ͬ���������õ��Ļ���ԭ��������

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// �����㷨��message�����ܵ���Ϣ��count��Ϣ���ȣ�key������Կ
void crypto(char message[], int length, int key);

// ���ַ��ֽ���ת16����
const char* toHexStr(const char* message, int length);

void test_stream()
{
	char msg[] = "Hello world!";
	int key = 10;
	int length = strlen(msg);

	printf("before encryption: %s\n", toHexStr(msg, length));

	// ����
	crypto(msg, length, key);
	printf("after encryption: %s\n", toHexStr(msg, length));

	// ����
	crypto(msg, length, key);
	printf("after decryption: %s\n", toHexStr(msg, length));

	system("pause");
}

void crypto(char message[], int length, int key)
{
	char key_stream = 0;
	int i = 0;

	// ����Կ��Ϊ����
	srand(key);

	for (int i = 0; i < length; ++i)
	{
		// ���������ĳ���һ�µ���Կ��
		key_stream = rand() & 0x00ff;
		// ����������Կ�������������õ�����
		message[i] ^= key_stream;
	}
}

const char* toHexStr(const char* message, int length)
{
#define BUFFER_SIZE 4 * 1024 + 1
	static const char CHAR_TABLE[] = "0123456789ABCDEF";
	static char buffer[BUFFER_SIZE];
	int i = 0, j = 0;
	int high = 0, low = 0;

	memset(buffer, 0, sizeof(buffer));
	while (i < length && j < BUFFER_SIZE)
	{
		// charֻռ1һ���ֽڣ����п���ֱ�Ӽ����4λ�͵�4λ
		high = message[i] / 16;
		low = message[i] % 16;
		buffer[j++] = CHAR_TABLE[high & 0xf];
		buffer[j++] = CHAR_TABLE[low & 0xf];
		i++;
	}

	return buffer;
}
