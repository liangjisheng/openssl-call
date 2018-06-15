
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/md5.h>

void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);

static struct test_st {
	unsigned char key[16];
	int key_len;
	unsigned char data[64];
	int data_len;
	unsigned char *digest;
} test[8] = {
	{
		"", 0, "More text test vectors to stuff up EBCDIC machines :-)", 54,
		(unsigned char *)"e9139d1e6ee064ef8cf514fc7dc83e86",
	},
	{
		{
			0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		}, 16, "Hi There", 8,
		(unsigned char *)"9294727a3638bb1c13f48ef8158bfc9d",
	},
	{
		"Jefe", 4, "what do ya want for nothing?", 28,
		(unsigned char *)"750c783e6ab0b503eaa86e310a5db738",
	},
	{
		{
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
				0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		}, 16, {
			0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
				0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
				0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
				0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
				0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd
		}, 50, (unsigned char *)"56be34521d144c88dbb8c733f0e8b3f6",
	},
	{
		"", 0, "My test data", 12,
		(unsigned char *)"61afdecb95429ef494d61fdee15990cabf0826fc"
	},
	{
		"", 0, "My test data", 12,
		(unsigned char *)"2274b195d90ce8e03406f4b526a47e0787a88a65479938f1a5baa3ce0f079776"
	},
	{
		"123456", 6, "My test data", 12,
		(unsigned char *)"bab53058ae861a7f191abe2d0145cbb123776a6369ee3f9d79ce455667e411dd"
	},
	{
		"12345", 5, "My test data again", 12,
		(unsigned char *)"7dbe8c764c068e3bcd6e6b0fbcd5e6fc197b15bb"
	}
};

static char *pt(unsigned char *md, unsigned int len);


int test_hmac()
{
	int i = 0;
	char *p = NULL;
	int err = 0;

#  ifdef CHARSET_EBCDIC
	ebcdic2ascii(test[0].data, test[0].data, test[0].data_len);
	ebcdic2ascii(test[1].data, test[1].data, test[1].data_len);
	ebcdic2ascii(test[2].key, test[2].key, test[2].key_len);
	ebcdic2ascii(test[2].data, test[2].data, test[2].data_len);
#  endif

	for (i = 0; i < 4; i++) 
	{
		p = pt(HMAC(EVP_md5(),
			test[i].key, test[i].key_len,
			test[i].data, test[i].data_len, NULL, NULL),
			MD5_DIGEST_LENGTH);

		if (strcmp(p, (char *)test[i].digest) != 0) 
		{
			printf("Error calculating HMAC on %d entry'\n", i);
			printf("got %s instead of %s\n", p, test[i].digest);
			err++;
		} 
		else
		{
			printf("%s\n", p);
			printf("test %d ok\n\n", i);
		}
	}



	HMAC_CTX ctx, ctx2;
	unsigned char buf[EVP_MAX_MD_SIZE] = {0};
	unsigned int len = 0;

	HMAC_CTX_init(&ctx);

	HMAC_Init_ex(&ctx, test[4].key, test[4].key_len, EVP_sha1(), NULL);
	HMAC_Update(&ctx, test[4].data, test[4].data_len);
	HMAC_Final(&ctx, buf, &len);
	disp(buf, len);
	
	memset(buf, 0, EVP_MAX_MD_SIZE);
	HMAC_Init_ex(&ctx, test[4].key, test[4].key_len, EVP_sha256(), NULL);
	HMAC_Update(&ctx, test[4].data, test[4].data_len);
	HMAC_Final(&ctx, buf, &len);
	disp(buf, len);

	memset(buf, 0, EVP_MAX_MD_SIZE);
	HMAC_Init_ex(&ctx, test[6].key, test[6].key_len, NULL, NULL);
	HMAC_Update(&ctx, test[6].data, test[6].data_len);
	HMAC_Final(&ctx, buf, &len);
	disp(buf, len);

	memset(buf, 0, EVP_MAX_MD_SIZE);
	HMAC_CTX_copy(&ctx2, &ctx);
	HMAC_Init_ex(&ctx2, test[7].key, test[7].key_len, EVP_sha1(), NULL);
	HMAC_Update(&ctx2, test[7].data, test[7].data_len);
	HMAC_Final(&ctx2, buf, &len);
	disp(buf, len);

	return 0;
}

static char *pt(unsigned char *md, unsigned int len)
{
	unsigned int i;
	static char buf[80];

	for (i = 0; i < len; i++)
		sprintf(&(buf[i * 2]), "%02x", md[i]);
	return (buf);
}

