
#include <stdio.h>
#include "openssl/ssl.h"
#include <openssl/bn.h>

#define ECDH_SIZE 33

void handleErrors();
void bn_hex_printf(const BIGNUM * a);
void bn_dec_printf(const BIGNUM * a);
void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);
void disp(const char *str, const void *pbuf, const int size);

int test_ecdh2()
{
	// alice
	EC_KEY *ecdh = EC_KEY_new();
	const EC_POINT *point = NULL;
	EC_POINT *point2c = NULL;
	const EC_GROUP *group = NULL;
	unsigned char pubkey[ECDH_SIZE] = {0};
	unsigned char shared[ECDH_SIZE] = {0};
	int len = 0;

	// Generate Public
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	EC_KEY_generate_key(ecdh);
	point = EC_KEY_get0_public_key(ecdh);
	group = EC_KEY_get0_group(ecdh);
	//bn_hex_printf(ecdh->priv_key);
	//bn_hex_printf(group->order);

	if (0 == (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pubkey,ECDH_SIZE, NULL)))
		handleErrors();
	printf("len = %d\n", len);

	// bob
	EC_KEY *ecdh2 = EC_KEY_new();
	const EC_POINT *point2 = NULL;
	EC_POINT *pointc = NULL;
	const EC_GROUP *group2 = NULL;
	unsigned char pubkey2[ECDH_SIZE] = {0};
	unsigned char shared2[ECDH_SIZE] = {0};
	int len2 = 0;

	// Generate Public
	ecdh2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	EC_KEY_generate_key(ecdh2);
	point2 = EC_KEY_get0_public_key(ecdh2);
	group2 = EC_KEY_get0_group(ecdh2);

	if (0 == (len = EC_POINT_point2oct(group2, point2, POINT_CONVERSION_COMPRESSED, pubkey2, ECDH_SIZE, NULL)))
		handleErrors();
	printf("len2 = %d\n", len);

	// alice compute share key
	point2c = EC_POINT_new(group);
	EC_POINT_oct2point(group, point2c, pubkey2, ECDH_SIZE, NULL);

	if (0 != EC_POINT_cmp(group, point2, point2c, NULL))
		handleErrors();
	if (0 == (len = ECDH_compute_key(shared, ECDH_SIZE, point2c, ecdh, NULL)))
		handleErrors();
	printf("len = %d\n", len);
	disp("shared", shared, len);

	// bob compute shared key
	pointc = EC_POINT_new(group2);
	EC_POINT_oct2point(group2, pointc, pubkey, ECDH_SIZE, NULL);

	if (0 != EC_POINT_cmp(group2, point, pointc, NULL))
		handleErrors();
	if (0 == (len2 = ECDH_compute_key(shared2, ECDH_SIZE, pointc, ecdh2, NULL)))
		handleErrors();
	printf("len2 = %d\n", len2);
	disp("shared2", shared2, len2);

	// alice
	EC_POINT_free(pointc);
	EC_KEY_free(ecdh);

	// bob
	EC_POINT_free(point2c);
	EC_KEY_free(ecdh2);

	return 0;
}
