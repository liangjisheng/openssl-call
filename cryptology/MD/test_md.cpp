
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

int test_md(char *lpszName)
{
	EVP_MD_CTX mdctx;
	const EVP_MD *md;
	char mess1[] = "Test Message";
	unsigned char md_value[EVP_MAX_MD_SIZE] = {0};
	unsigned int md_len = 0;
	int  i = 0;

	OpenSSL_add_all_digests();

	md = EVP_get_digestbyname(lpszName);

	if (!md)
	{
		printf("Unknown message digest %s\n", lpszName);
		return -1;
	}

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	EVP_DigestUpdate(&mdctx, mess1, strlen(mess1));
	EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);

	printf("%s: ", lpszName);
	disp(md_value, md_len);

	return 0;
}

