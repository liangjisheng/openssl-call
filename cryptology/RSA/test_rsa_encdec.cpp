
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#define PRIKEY "prikey.pem"
#define PUBKEY "pubkey.pem"
#define BUFFSIZE 4096
#define KEY_LENGTH 2048					// 密钥长度
#define PUB_KEY_FILE "pubkey.pem"		// 公钥路径
#define PRI_KEY_FILE "prikey.pem"		// 私钥路径

void generateRSAKey();

char *my_encrypt(char *str, char *pubkey_path)
{
	RSA *rsa = NULL;
	FILE *fp = NULL;
	char *en = NULL;
	int len = 0;
	int rsa_len = 0;

	if ((fp = fopen(pubkey_path, "r")) == NULL)
		return NULL;

	// 读取公钥pem pubkey格式PEM使用PEM_read_RSAPublicKey()
	// RSAPublicKey格式公钥证书
	// -----BEGIN RSA PUBLIC KEY-----
	// -----END RSA PUBLIC KEY-----
	if ((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL)
		return NULL;

	RSA_print_fp(stdout, rsa, 0);

	len = strlen(str);
	rsa_len = RSA_size(rsa);

	en = (char *)malloc(rsa_len + 1);
	memset(en, 0, rsa_len + 1);

	if (RSA_public_encrypt(rsa_len, (unsigned char *)str, (unsigned char *)en, rsa, RSA_NO_PADDING)	< 0)
	{
		RSA_free(rsa);
		fclose(fp);
		return NULL;
	}

	RSA_free(rsa);
	fclose(fp);

	return en;
}

char *my_decrypt(char *str, char *prikey_path)
{
	RSA *rsa = NULL;
	FILE *fp = NULL;
	char *de = NULL;
	int rsa_len = 0;

	if ((fp = fopen(prikey_path, "r")) == NULL)
		return NULL;

	if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL)
		return NULL;

	RSA_print_fp(stdout, rsa, 0);

	rsa_len = RSA_size(rsa);
	de = (char *)malloc(rsa_len + 1);
	memset(de, 0, rsa_len + 1);

	if (RSA_private_decrypt(rsa_len, (unsigned char *)str, (unsigned char *)de, rsa, RSA_NO_PADDING) < 0)
	{
		RSA_free(rsa);
		fclose(fp);
		return NULL;
	}

	RSA_free(rsa);
	fclose(fp);

	return de;
}

void test_RSA_2()
{
	generateRSAKey();

	char *src = "hello, world!";
	char *en = NULL;
	char *de = NULL;
	printf("src is : %s\n", src);

	en = my_encrypt(src, PUBKEY);
	printf("enc is: %s\n", en);

	de = my_decrypt(en, PRIKEY);
	printf("dec is: %s\n", de);

	if (en != NULL)
		free(en);

	if (de != NULL)
		free(de);
}

void generateRSAKey()
{
	// 公私密钥对
	size_t pri_len, pub_len;
	char *pri_key = NULL;
	char *pub_key = NULL;

	// 产生RSA密钥对
	RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
	printf("BIGNUM: %s\n\n", BN_bn2hex(keypair->n));

	// 读取到密钥对BIO结构中
	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	// 获取长度
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// 读取密钥对到字符串
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	printf("Private key: \n");
	printf("%s\n", pri_key);
	printf("Public key: \n");
	printf("%s\n", pub_key);

	// 存储到磁盘(这种存储方式是begin rsa public key/ begin rsa private key开头的)
	FILE *pubFile = fopen(PUB_KEY_FILE, "w");
	if (pubFile == NULL)
	{
		assert(false);
		return ;
	}

	fputs(pub_key, pubFile);
	fclose(pubFile);

	FILE *priFile = fopen(PRI_KEY_FILE, "w");
	if (NULL == priFile)
	{
		assert(false);
		return ;
	}

	fputs(pri_key, priFile);
	fclose(priFile);

	// 内存释放
	RSA_free(keypair);
	BIO_free_all(pri);
	BIO_free_all(pub);

	if (pri_key)
		free(pri_key);
	pri_key = NULL;

	if (pub_key)
		free(pub_key);
	pub_key = NULL;
}

