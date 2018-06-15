
#include <stdio.h>
#include <stdlib.h>

#include <openssl\des.h>

void test_DES_ECB_1()
{
	DES_cblock key;				// 密钥块
	DES_random_key(&key);		// 生成随机密钥

	DES_key_schedule schedule;
	DES_set_key_checked(&key, &schedule);	// 转换成schedule

	const_DES_cblock input = "hehehe";
	DES_cblock output;

	printf("clearText:%s\n", input);

	// encrypt
	DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT);
	printf("cipherText:");
	int i;
	for (i = 0; i < sizeof(input); ++i)
		printf("%02x", output[i]);
	printf("\n");

	// decrypt
	DES_ecb_encrypt(&output, &input, &schedule, DES_DECRYPT);
	printf("clearText:%s\n", input);
}

