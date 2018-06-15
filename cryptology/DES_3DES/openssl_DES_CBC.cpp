
#include <stdio.h>
#include <string.h>

#include "openssl\des.h"

int test_DES_CBC()
{
	char *keystring = "this is my key";
	DES_cblock key;
	DES_key_schedule key_schedule;

	// 生成一个key
	DES_string_to_key(keystring, &key);
	printf("key:");
	for (int i = 0; i < 8; ++i)
		printf("%02x", key[i]);
	printf("\n");

	if (DES_set_key_checked(&key, &key_schedule) != 0)
	{
		printf("convert to key_schedule failed.\n");
		return -1;
	}

	unsigned char input[] = "this is a text being encrypted by openssl";
	size_t len = (sizeof(input) + 7) / 8 * 8;
	unsigned char *output = (unsigned char *)malloc(len + 1);

	DES_cblock ivec;		// IV
	memset((char *)&ivec, 0, sizeof(ivec));

	// encrypt
	DES_ncbc_encrypt(input, output, sizeof(input), &key_schedule, &ivec, DES_ENCRYPT);
	printf("cipherText:");
	for (size_t i = 0; i < len; ++i)
		printf("%02x", output[i]);
	printf("\n");

	memset(&ivec, 0, sizeof(ivec));
	// decrypt
	unsigned char ucszClearText[1024] = {0};
	DES_ncbc_encrypt(output, ucszClearText, len, &key_schedule, &ivec, 0);
	printf("clearText:%s\n", ucszClearText);

	if (output)
		free(output);
	output = NULL;

	return 0;
}

