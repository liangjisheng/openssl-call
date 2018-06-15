
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

static void hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
	int n = 0;

	fprintf(f, "%s", title);
	for (; n < l; ++n)
	{
		if ((n % 16) == 0)
			fprintf(f, "\n%04x", n);
		fprintf(f, " %02x", s[n]);
	}
	fprintf(f, "\n");
}

int main(int argc, char *argv[])
{
	unsigned char szKey[16] = {0};
	AES_KEY aes;

	unsigned char szPlainText[AES_BLOCK_SIZE * 4] = 
	{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',  
		'0', '1', '2', '3', '4', '5', '6', '7', '0', '1', '2', '3', '4', '5', '6', '7',  
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'i',  
		'0', '1', '2', '3', '4', '5', '6', '7', '0', '1', '2', '3', '4', '5', '6', '7'
	};
	unsigned char szCipherText[AES_BLOCK_SIZE * 4] = {0};
	unsigned char szCheckText[AES_BLOCK_SIZE * 4] = {0};
	unsigned char szIV[AES_BLOCK_SIZE * 4] = {0};
	unsigned char szSaveIV[AES_BLOCK_SIZE * 4] = {0};
	int nr_of_bits = 0, nr_of_bytes = 0;

	// Generate random
	RAND_pseudo_bytes(szKey, sizeof(szKey));
	RAND_pseudo_bytes(szSaveIV, sizeof(szSaveIV));
	hexdump(stdout, "== szKey ==", szKey, sizeof(szKey));
	hexdump(stdout, "== IV ==", szIV, sizeof(szIV));
	printf("\n");
	hexdump(stdout, "== szPlainText ==", szPlainText, sizeof(szPlainText));
	printf("\n");

	// Encrypt
	memcpy(szIV, szSaveIV, sizeof(szIV));
	nr_of_bits = 8 * sizeof(szKey);
	AES_set_encrypt_key(szKey, nr_of_bits, &aes);
	nr_of_bytes = sizeof(szPlainText);
	// szIV will change
	AES_cbc_encrypt(szPlainText, szCipherText, nr_of_bytes, &aes, szIV, AES_ENCRYPT);
	hexdump(stdout, "== szCipherText ==", szCipherText, sizeof(szCipherText));
	printf("\n");
	hexdump(stdout, "== szIV changed ==", szIV, sizeof(szIV));
	printf("\n");

	// Decrypt
	memcpy(szIV, szSaveIV, sizeof(szIV));
	nr_of_bytes = sizeof(szCipherText);
	AES_set_decrypt_key(szKey, nr_of_bits, &aes);
	AES_cbc_encrypt(szCipherText, szCheckText, nr_of_bytes, &aes, szIV, AES_DECRYPT);
	hexdump(stdout, "== szCheckText ==", szCheckText, sizeof(szCheckText));
	printf("\n");

	getchar();
	return 0;
}

