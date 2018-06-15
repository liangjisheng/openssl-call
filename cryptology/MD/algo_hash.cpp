
#include "algo_hash.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <openssl/evp.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

using namespace std;

void HashInit()
{
	OpenSSL_add_all_digests();
}

int HashEncode(const char *algo, const char *input, unsigned int input_length, 
	unsigned char *output, unsigned int &output_length)
{
	EVP_MD_CTX ctx;
	const EVP_MD *md = EVP_get_digestbyname(algo);
	if (!md)
	{
		printf("Unknown message digest algorithm: %s\n", algo);
		return -1;
	}

	EVP_MD_CTX_init(&ctx);
	EVP_DigestInit_ex(&ctx, md, NULL);
	EVP_DigestUpdate(&ctx, input, input_length);
	EVP_DigestFinal_ex(&ctx, output, &output_length);
	EVP_MD_CTX_cleanup(&ctx);

	return 0;
}

int test_algo_hash(const char *algo)
{
	if (NULL == algo)
	{
		printf("Algorithm is required!\n");
		return -1;
	}

	HashInit();

	string input = "Test Message";
	unsigned char *output = (unsigned char *)malloc(EVP_MAX_MD_SIZE * sizeof(unsigned char));
	memset(output, 0, EVP_MAX_MD_SIZE);
	unsigned int output_length = 0;
	int result = HashEncode(algo, input.c_str(), input.size(), output, output_length);

	printf("Result: %d\n", result);
	printf("Input length: %d\n", input.size());
	printf("Input: %s\n", input.c_str());
	printf("Output length: %d\n", output_length);
	printf("Output: ");
	disp(output, output_length);

	if (NULL != output)
	{
		free(output);
		output = NULL;
	}

	return 0;
}

