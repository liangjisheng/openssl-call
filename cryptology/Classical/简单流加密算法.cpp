
// 对一个数据进行两次相同的异或运算得到的还是原来的数据

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 加密算法，message被加密的消息，count消息长度，key加密密钥
void crypto(char message[], int length, int key);

// 将字符字节流转16进制
const char* toHexStr(const char* message, int length);

void test_stream()
{
	char msg[] = "Hello world!";
	int key = 10;
	int length = strlen(msg);

	printf("before encryption: %s\n", toHexStr(msg, length));

	// 加密
	crypto(msg, length, key);
	printf("after encryption: %s\n", toHexStr(msg, length));

	// 解密
	crypto(msg, length, key);
	printf("after decryption: %s\n", toHexStr(msg, length));

	system("pause");
}

void crypto(char message[], int length, int key)
{
	char key_stream = 0;
	int i = 0;

	// 以密钥作为种子
	srand(key);

	for (int i = 0; i < length; ++i)
	{
		// 生成与密文长度一致的密钥流
		key_stream = rand() & 0x00ff;
		// 将明文与密钥流进行异或运算得到密文
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
		// char只占1一个字节，所有可以直接计算高4位和低4位
		high = message[i] / 16;
		low = message[i] % 16;
		buffer[j++] = CHAR_TABLE[high & 0xf];
		buffer[j++] = CHAR_TABLE[low & 0xf];
		i++;
	}

	return buffer;
}
