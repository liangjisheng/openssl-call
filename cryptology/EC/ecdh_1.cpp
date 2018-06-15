
#include <stdio.h>
#include <openssl/ssl.h>

#include "func.h"

#ifdef _DEBUG
#include <vld.h>
#endif

#define ECDH_SIZE 33
#define ECDH_SIZE1 65

void handleErrors();
void bn_hex_printf(const BIGNUM * a);
void bn_dec_printf(const BIGNUM * a);
void disp(const char *data, const int nLen);
void disp(const unsigned char *data, const int nLen);
void disp(const char *str, const void *pbuf, const int size);

EC_GROUP *create_curve(const char *p, const char *a, const char *b, const char *order, 
	const char *x, const char *y)
{
	int nRet = 0;
	BN_CTX *ctx = NULL;
	EC_GROUP *curve;
	BIGNUM *bn_a, *bn_b, *bn_p, *bn_order, *bn_x, *bn_y, *bn_cofactor;
	EC_POINT *generator;

	if (NULL == (ctx = BN_CTX_new()))
	{
		handleErrors();
		return NULL;
	}

	bn_p = BN_new();
	printf("p_hex: %s\n", p);
	nRet = BN_hex2bn(&bn_p, p);
	printf("len of p: %d\n", nRet);
	printf("dec p_hex: ");
	bn_dec_printf(bn_p);
	printf("hex p_hex: ");
	bn_hex_printf(bn_p);
	printf("\n");

	bn_a = BN_new();
	printf("a_hex: %s\n", a);
	nRet = BN_hex2bn(&bn_a, a);
	printf("len of a: %d\n", nRet);
	printf("dec a_hex: ");
	bn_dec_printf(bn_a);
	printf("hex a_hex: ");
	bn_hex_printf(bn_a);
	printf("\n");

	bn_b = BN_new();
	printf("b_hex: %s\n", b);
	nRet = BN_hex2bn(&bn_b, b);
	printf("len of b: %d\n", nRet);
	printf("dec b_hex: ");
	bn_dec_printf(bn_b);
	printf("hex b_hex: ");
	bn_hex_printf(bn_b);
	printf("\n");

	bn_order = BN_new();
	printf("order_hex: %s\n", order);
	nRet = BN_hex2bn(&bn_order, order);
	printf("len of order: %d\n", nRet);
	printf("dec order_hex: ");
	bn_dec_printf(bn_order);
	printf("hex order_hex: ");
	bn_hex_printf(bn_order);
	printf("\n");

	bn_x = BN_new();
	printf("x_hex: %s\n", x);
	nRet = BN_hex2bn(&bn_x, x);
	printf("len of x: %d\n", nRet);
	printf("dec x_hex: ");
	bn_dec_printf(bn_x);
	printf("hex x_hex: ");
	bn_hex_printf(bn_x);
	printf("\n");

	bn_y = BN_new();
	printf("y_hex: %s\n", y);
	nRet = BN_hex2bn(&bn_y, y);
	printf("len of y: %d\n", nRet);
	printf("dec y_hex: ");
	bn_dec_printf(bn_y);
	printf("hex y_hex: ");
	bn_hex_printf(bn_y);
	printf("\n");

	bn_cofactor = BN_new();
	BN_one(bn_cofactor);
	printf("dec cofactor_hex: ");
	bn_dec_printf(bn_cofactor);
	printf("hex cofactor_hex: ");
	bn_hex_printf(bn_cofactor);
	printf("\n");

	// create the curve
	curve = EC_GROUP_new_curve_GFp(bn_p, bn_a, bn_b, ctx);
	if (NULL == curve)
	{
		handleErrors();
		BN_free(bn_p);
		BN_free(bn_a);
		BN_free(bn_b);
		BN_free(bn_order);
		BN_free(bn_x);
		BN_free(bn_y);
		BN_free(bn_cofactor);
		BN_CTX_free(ctx);
		return NULL;
	}

	// create the generator
	generator = EC_POINT_new(curve);
	if (NULL == generator)
	{
		handleErrors();
		EC_POINT_free(generator);
		BN_free(bn_p);
		BN_free(bn_a);
		BN_free(bn_b);
		BN_free(bn_order);
		BN_free(bn_x);
		BN_free(bn_y);
		BN_free(bn_cofactor);
		BN_CTX_free(ctx);
		return NULL;
	}

	nRet = EC_POINT_set_affine_coordinates_GFp(curve, generator, bn_x, bn_y, ctx);
	if (1 != nRet)
	{
		handleErrors();
		EC_POINT_free(generator);
		BN_free(bn_p);
		BN_free(bn_a);
		BN_free(bn_b);
		BN_free(bn_order);
		BN_free(bn_x);
		BN_free(bn_y);
		BN_free(bn_cofactor);
		BN_CTX_free(ctx);
		return NULL;
	}

	// set the generator and the order
	nRet = EC_GROUP_set_generator(curve, generator, bn_order, bn_cofactor);
	if (1 != nRet)
	{
		handleErrors();
		EC_POINT_free(generator);
		BN_free(bn_p);
		BN_free(bn_a);
		BN_free(bn_b);
		BN_free(bn_order);
		BN_free(bn_x);
		BN_free(bn_y);
		BN_free(bn_cofactor);
		BN_CTX_free(ctx);
		return NULL;
	}

	EC_POINT_free(generator);
	BN_free(bn_p);
	BN_free(bn_a);
	BN_free(bn_b);
	BN_free(bn_order);
	BN_free(bn_x);
	BN_free(bn_y);
	BN_free(bn_cofactor);
	BN_CTX_free(ctx);

	return curve;
}

void GetCurveParam(const EC_GROUP *group)
{
	printf("--------------------------start GetCurveParam(const EC_GROUP *group)-------------------------\n\n");

	if (NULL == group)
		return ;

	int nRet = 0, len = 0;

	BN_CTX *ctx = NULL;
	if (NULL == (ctx = BN_CTX_new()))
	{
		handleErrors();
		return ;
	}

	// ��ȡ��Բ���ߵĲ���
	BIGNUM *p, *a, *b;
	p = BN_new();
	a = BN_new();
	b = BN_new();
	nRet = EC_GROUP_get_curve_GFp(group, p, a, b, NULL);
	if (1 == nRet)
	{
		printf("p: ");
		bn_hex_printf(p);
		printf("\n");
		printf("a: ");
		bn_hex_printf(a);
		printf("\n");
		printf("b: ");
		bn_hex_printf(b);
		printf("\n");
	}
	else
	{
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_CTX_free(ctx);
		return ;
	}

	// ��ȡ��Բ����field type
	const EC_METHOD *method = EC_GROUP_method_of(group);
	int get_nid = EC_METHOD_get_field_type(method);
	printf("field type = %d\n", get_nid);	// 406
	printf("\n");

	// ��ȡ��Բ���߶�Ӧ��id
	get_nid = EC_GROUP_get_curve_name(group);
	printf("get_nid = %d\n", get_nid);	// 415
	printf("\n");

	// ��ȡG��Ľ�
	BIGNUM *order = BN_new();
	nRet = EC_GROUP_get_order(group, order, ctx);
	if (1 == nRet)
	{
		printf("n: ");
		bn_hex_printf(order);
		printf("\n");
	}
	else
	{
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_CTX_free(ctx);
		return ;
	}

	// ��ȡ��Բ���ߵ�������
	BIGNUM *cafactor = BN_new();
	nRet = EC_GROUP_get_cofactor(group, cafactor, ctx);
	if (1 == nRet)
	{
		printf("cofactor: ");
		bn_hex_printf(cafactor);
		printf("\n");
	}
	else
	{
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_free(cafactor);
		BN_CTX_free(ctx);
		return ;
	}

	// ��Բ���ߵĳ������﷨
	int asn1_flag = EC_GROUP_get_asn1_flag(group);
	printf("asn1_flag: %d\n\n", asn1_flag);

	/** Enum for the point conversion form as defined in X9.62 (ECDSA)
	 *  for the encoding of a elliptic curve point (x,y) */
	point_conversion_form_t format = EC_GROUP_get_point_conversion_form(group);
	printf("point_conversion_form_t: %d\n\n", (int)format);

	// ��ȡ����
	size_t seedLen = EC_GROUP_get_seed_len(group);
	printf("seedLen: %d\n", seedLen);
	unsigned char *seed = EC_GROUP_get0_seed(group);
	disp("seed", seed, seedLen);
	//printf("seed: %s\n\n", seed);
	// free(seed);
	// seed = NULL;

	// the number of bits needed to represent a field element
	int bits = EC_GROUP_get_degree(group);
	printf("field element bits: %d\n\n", bits);

	// ��ȡ����ԪG�������
	const EC_POINT *G_point = EC_GROUP_get0_generator(group);
	unsigned char G_pointoct[ECDH_SIZE] = {0};
	len = EC_POINT_point2oct(group, G_point, POINT_CONVERSION_COMPRESSED, G_pointoct, ECDH_SIZE, ctx);
	if (0 == len)
	{
		handleErrors();
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_free(cafactor);
		BN_CTX_free(ctx);
		return ;
	}
	else
	{
		printf("len = %d\n", len);
		disp("G_point:", G_pointoct, len);
		printf("\n");
	}

	EC_POINT *point_oct = EC_POINT_new(group);
	nRet = EC_POINT_oct2point(group, point_oct, G_pointoct, len, ctx);
	nRet = EC_POINT_cmp(group, point_oct, G_point, ctx);
	if (0 == nRet)
		printf("points are equal\n\n");
	else
	{
		handleErrors();
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_free(cafactor);
		EC_POINT_free(point_oct);
		BN_CTX_free(ctx);
		return ;
	}

	memset(G_pointoct, 0, sizeof(G_pointoct));
	BIGNUM *G_BigNum = BN_new();
	G_BigNum = EC_POINT_point2bn(group, G_point, POINT_CONVERSION_COMPRESSED, G_BigNum, ctx);
	printf("dec G_BigNum_hex: ");
	bn_dec_printf(G_BigNum);
	printf("\n");
	printf("hex G_BigNum_hex: ");
	bn_hex_printf(G_BigNum);
	printf("\n");

	EC_POINT *point_bn = EC_POINT_new(group);
	point_bn = EC_POINT_bn2point(group, G_BigNum, point_bn, ctx);
	nRet = EC_POINT_cmp(group, point_bn, G_point, ctx);
	if (0 == nRet)
		printf("points are equal\n\n");
	else
	{
		handleErrors();
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_free(cafactor);
		EC_POINT_free(point_oct);
		EC_POINT_free(point_bn);
		BN_CTX_free(ctx);
		return ;
	}

	char *pPointBigNum = EC_POINT_point2hex(group, G_point, POINT_CONVERSION_COMPRESSED, ctx);
	if (pPointBigNum)
	{
		printf("hex G_BigNum_hex: ");
		printf("%s\n", pPointBigNum);
		printf("\n");
	}
	else
	{
		handleErrors();
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_free(cafactor);
		EC_POINT_free(point_oct);
		EC_POINT_free(point_bn);
		BN_CTX_free(ctx);
		return ;
	}

	EC_POINT *point_hex = EC_POINT_new(group);
	point_hex = EC_POINT_hex2point(group, pPointBigNum, point_hex, ctx);
	nRet = EC_POINT_cmp(group, point_hex, G_point, ctx);
	if (0 == nRet)
		printf("points are equal\n\n");
	else
	{
		handleErrors();
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_free(cafactor);
		EC_POINT_free(point_oct);
		EC_POINT_free(point_bn);
		EC_POINT_free(point_hex);
		BN_CTX_free(ctx);
		return ;
	}

	BIGNUM *x, *y;
	x = BN_new();
	y = BN_new();
	nRet = EC_POINT_get_affine_coordinates_GFp(group, G_point, x, y, ctx);
	if (1 == nRet)
	{
		printf("hex Gx: ");
		bn_hex_printf(x);
		printf("\n");
		printf("hex Gy: ");
		bn_hex_printf(y);
		printf("\n\n");
	}
	else
	{
		handleErrors();
		BN_free(x);
		BN_free(y);
		BN_free(p);
		BN_free(a);
		BN_free(b);
		BN_free(order);
		BN_free(cafactor);
		EC_POINT_free(point_oct);
		EC_POINT_free(point_bn);
		EC_POINT_free(point_hex);
		BN_CTX_free(ctx);
		return ;
	}

	BN_free(x);
	BN_free(y);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(order);
	BN_free(cafactor);
	EC_POINT_free(point_oct);
	EC_POINT_free(point_bn);
	EC_POINT_free(point_hex);
	BN_CTX_free(ctx);

	printf("-----------------------end GetCurveParam(const EC_GROUP *group)------------------------\n\n");
}

void GetCurveParam(int nid)
{
	// ����һ����Բ���߽ṹ��
	EC_KEY *ecdh = EC_KEY_new();
	// ���ض���Բ���߸�ֵ��ecdh
	ecdh = EC_KEY_new_by_curve_name(nid);
	// ��ȡ���ߵĻ���G
	const EC_GROUP *group = EC_KEY_get0_group(ecdh);

	GetCurveParam(group);	
}

// ��ȡOpenSSL������Բ���ߵ������
void GetCurveParam()
{
	for (int nid = 409; nid <= 415; ++nid)
		GetCurveParam(nid);
	for (int nid = 684; nid <= 690; ++nid)
		GetCurveParam(nid);
	for (int nid = 693; nid <= 696; ++nid)
		GetCurveParam(nid);
	for (int nid = 699; nid <= 745; ++nid)
		GetCurveParam(nid);
	for (int nid = 749; nid <= 750; ++nid)
		GetCurveParam(nid);
}

EC_KEY* genECDHpubkey(unsigned char *pubkey)
{
	int len = 0, nRet = 0;
	EC_KEY *ecdh = EC_KEY_new();
	// Generate Public, ��ȡ������Բ���ߵĻ���G
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);	//NID_secp521r1
	// ��ȡ���ߵĻ���G
	const EC_GROUP *group = EC_KEY_get0_group(ecdh);	

	// �������һ����������Ϊ˽Կk�����ݻ���G������K = kG;��Ϊ��Կ
	EC_KEY_generate_key(ecdh);
	// ��ȡ��Կ
	const EC_POINT *point = EC_KEY_get0_public_key(ecdh);
	// ����Կת��Ϊ��λ�ֽ��ַ���pubkey,�����ַ�������
	len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pubkey, ECDH_SIZE, NULL);
	if (0 == len)
		handleErrors();
	//printf("len = %d\n", len);
	//disp("pubkey", pubkey, len);
	//printf("\n");

	return ecdh;
}

unsigned char* genECDHsharedsecret(EC_KEY *ecdh, unsigned char *peerkey, size_t secret_len)
{
	int len = 0;
	unsigned char *shared = (unsigned char *)malloc(secret_len);
	memset(shared, 0, secret_len);
	const EC_GROUP *group = EC_KEY_get0_group(ecdh);
	// ��group�����д����µĵ�
	EC_POINT *point_peer = EC_POINT_new(group);
	// ����λ�ֽ��ַ���ת��ΪEC_POINT����,secret_len����ĳ��ȱ������Կ�������ٴ�1���ֽڣ�
	// ����ת����ʧ��
	int nRet = EC_POINT_oct2point(group, point_peer, peerkey, secret_len, NULL);

	// computer shared key
	len = ECDH_compute_key(shared, secret_len, point_peer, ecdh, NULL);
	if (0 == len)
		handleErrors();
	printf("len = %d\n", len);
	disp("shared", shared, secret_len);

	return shared;
}

void testECDH()
{
	unsigned char *keydata = (unsigned char *)malloc(ECDH_SIZE);
	unsigned char *keydata2 = (unsigned char *)malloc(ECDH_SIZE);
	memset(keydata, 0, ECDH_SIZE);
	memset(keydata2, 0, ECDH_SIZE);

	EC_KEY *ecdh = genECDHpubkey(keydata);
	EC_KEY *ecdh2 = genECDHpubkey(keydata2);
	disp("pubkey1", keydata, ECDH_SIZE);
	disp("pubkey2", keydata2, ECDH_SIZE);

	// ���ع�����Կ
	unsigned char *ECDH_keydata = genECDHsharedsecret(ecdh2, keydata, ECDH_SIZE);
	unsigned char *ECDH_keydata2 = genECDHsharedsecret(ecdh, keydata2, ECDH_SIZE);

	printf("To the end\n");
	free(keydata);
	free(keydata2);

	EC_KEY_free(ecdh);
	EC_KEY_free(ecdh2);

	free(ECDH_keydata);
	free(ECDH_keydata2);
}

// ʹ���Զ������߽�����ԿЭ��
void testECDH_selfCurve()
{
	int nRet = 0, len = 0;

	BN_CTX *ctx = NULL;
	if (NULL == (ctx = BN_CTX_new()))
		handleErrors();

	//BIGNUM *bn_pubkey, *bn_pubkey2;
	//unsigned char pubkey[ECDH_SIZE] = {0};
	//string strPubHex("038BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262");
	//string strPubHex("7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5Eab");
		//544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D");
	//string strPub;
	//MyHEX_BYTES(strPubHex, strPubHex.size(), strPub);
	//memcpy(pubkey, strPub.c_str(), strPub.size());
	//disp("pubkey", pubkey, ECDH_SIZE);

	//unsigned char pubkey2[ECDH_SIZE1] = {0};
	//strPubHex = "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57";
	//strPub = "";
	//MyHEX_BYTES(strPubHex, strPubHex.size(), strPub);
	//memcpy(pubkey2, strPub.c_str(), strPub.size());
	//disp("pubkey2", pubkey2, ECDH_SIZE1 - 1);

	//unsigned char pubkey[] = "7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E";
		//544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D";
	//unsigned char pubkey2[] = "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57";
		//30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54";

	//bn_pubkey = BN_new();
	//nRet = BN_hex2bn(&bn_pubkey, (char *)pubkey);
	//printf("hex pubkey: 0x%s\n", pubkey);
	//printf("dec pubkey: ");
	//bn_dec_printf(bn_pubkey);
	//printf("hex pubkey: ");
	//bn_hex_printf(bn_pubkey);
	//printf("\n");

	//bn_pubkey2 = BN_new();
	//nRet = BN_hex2bn(&bn_pubkey2, (char *)pubkey2);
	//printf("hex pubkey2: 0x%s\n", pubkey2);
	//printf("dec pubkey2: ");
	//bn_dec_printf(bn_pubkey2);
	//printf("hex pubkey2: ");
	//bn_hex_printf(bn_pubkey2);
	//printf("\n");

	unsigned char prikey[] = "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99";
	unsigned char prikey2[] = "498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560";

	// ����ָ����˽Կ����ʾ
	BIGNUM *bn_prikey, *bn_prikey2;
	bn_prikey = BN_new();
	nRet = BN_hex2bn(&bn_prikey, (char *)prikey);
	printf("hex prikey: 0x%s\n", prikey);
	printf("dec prikey: ");
	bn_dec_printf(bn_prikey);
	printf("hex prikey: ");
	bn_hex_printf(bn_prikey);
	printf("\n");

	bn_prikey2 = BN_new();
	nRet = BN_hex2bn(&bn_prikey2, (char *)prikey2);
	printf("hex prikey2: 0x%s\n", prikey2);
	printf("dec prikey2: ");
	bn_dec_printf(bn_prikey2);
	printf("hex prikey2: ");
	bn_hex_printf(bn_prikey2);
	printf("\n");

	const char *p = "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377";
	const char *a = "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9";
	const char *b = "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6";
	const char *x = "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262";
	const char *y = "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997";
	const char *order = "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7";
	//const char *cofactor = "1";

	// ʹ��ָ������Բ���������������Բ����,����������������ֵ�鿴
	const EC_GROUP *group = create_curve(p, a, b, order, x, y);
	nRet = EC_GROUP_check(group, ctx);	// ���group�������Բ�����Ƿ����
	GetCurveParam(group);				// �����Բ���߸�������ֵ

	EC_KEY *ecdh = EC_KEY_new();						// �½���Կ�ṹ��
	nRet = EC_KEY_set_group(ecdh, group);				// �����Զ������Բ����
	// ���ɹ�˽Կ�������������õĹ�Կ��˽Կ��������仰��û��������
	nRet = EC_KEY_generate_key(ecdh);

	nRet = EC_KEY_set_private_key(ecdh, bn_prikey);		// ����˽Կ

	// ��ȡEC_KEY�е���Բ����group1���������洴��group�ıȽ�
	const EC_GROUP *group1 = EC_KEY_get0_group(ecdh);
	nRet = EC_GROUP_cmp(group, group1, ctx);

	// �½���Բ���߹�Կ
	EC_POINT *point_pub = EC_POINT_new(group);
	// ��Բ���ߵĵ�˼��㣬��generator(group)��˽Կbn_prikey��˵õ���Կpoint_pub
	nRet = EC_POINT_mul(group, point_pub, bn_prikey, NULL, NULL, ctx);

	// �����Կx����
	unsigned char puboct[ECDH_SIZE] = {0};
	len = EC_POINT_point2oct(group, point_pub, POINT_CONVERSION_COMPRESSED, puboct, ECDH_SIZE, ctx);
	if (0 == len)
		handleErrors();
	printf("len = %d\n", len);
	disp("point_pub:", puboct, len);
	printf("\n");

	// �����Կx,y����
	BIGNUM *bn_x, *bn_y;
	bn_x = BN_new();
	bn_y = BN_new();
	nRet = EC_POINT_get_affine_coordinates_GFp(group, point_pub, bn_x, bn_y, ctx);
	if (1 == nRet)
	{
		printf("hex pub_x: ");
		bn_hex_printf(bn_x);
		printf("hex pub_y: ");
		bn_hex_printf(bn_y);
		printf("\n");
	}

	// ���ù�Կ
	nRet = EC_KEY_set_public_key(ecdh, point_pub);

	//EC_KEY_generate_key������һ�������k��Ϊ˽Կ��������K=kG��Ϊ��Կ
	//���ܵ����������EC_KEY_generate_key�������ı�˽Կ
	//nRet = EC_KEY_generate_key(ecdh);
	const BIGNUM *getprikey = EC_KEY_get0_private_key(ecdh);			// ��ȡ˽Կ�����
	printf("hex prikey: ");
	bn_hex_printf(const_cast<BIGNUM *>(getprikey));
	printf("\n");
	const EC_POINT *getpubkey = EC_KEY_get0_public_key(ecdh);	// ��ȡ��Կ���жϺͼ�����Ƿ�һ��
	nRet = EC_POINT_cmp(group, point_pub, getpubkey, ctx);
	if (0 == nRet)
		printf("points are equal\n\n");


	EC_KEY *ecdh2 = EC_KEY_new();						// �½���Կ�ṹ��
	nRet = EC_KEY_set_group(ecdh2, group);				// �����Զ������Բ����
	nRet = EC_KEY_set_private_key(ecdh2, bn_prikey2);	// ����˽Կ

	EC_POINT *point_pub2 = EC_POINT_new(group);
	nRet = EC_POINT_mul(group, point_pub2, bn_prikey2, NULL, NULL, ctx);
	unsigned char puboct2[ECDH_SIZE] = {0};
	len = EC_POINT_point2oct(group, point_pub2, POINT_CONVERSION_COMPRESSED, puboct2, ECDH_SIZE, ctx);
	if (0 == len)
		handleErrors();
	printf("len = %d\n", len);
	disp("point_pub2:", puboct2, len);
	printf("\n");

	nRet = EC_POINT_get_affine_coordinates_GFp(group, point_pub2, bn_x, bn_y, ctx);
	if (1 == nRet)
	{
		printf("hex pub2_x: ");
		bn_hex_printf(bn_x);
		printf("hex pub2_y: ");
		bn_hex_printf(bn_y);
		printf("\n");
	}
	//NID_X9_62_prime_field
	// ���ù�Կ
	nRet = EC_KEY_set_public_key(ecdh2, point_pub2);

	//nRet = EC_KEY_generate_key(ecdh2);
	const BIGNUM *getprikey2 = EC_KEY_get0_private_key(ecdh2);
	printf("hex prikey2: ");
	bn_hex_printf(const_cast<BIGNUM *>(getprikey2));
	printf("\n");
	const EC_POINT *getpubkey2 = EC_KEY_get0_public_key(ecdh2);
	nRet = EC_POINT_cmp(group, point_pub2, getpubkey2, ctx);
	if (0 == nRet)
		printf("points are equal\n\n");


	// ���㹲����Կ
	unsigned char shared[ECDH_SIZE] = {0};
	len = ECDH_compute_key(shared, ECDH_SIZE, point_pub, ecdh2, NULL);
	if (0 == len)
		handleErrors();
	printf("len = %d\n", len);
	disp("shared", shared, len);

	unsigned char shared2[ECDH_SIZE] = {0};
	len = ECDH_compute_key(shared2, ECDH_SIZE, point_pub2, ecdh, NULL);
	if (0 == len)
		handleErrors();
	printf("len = %d\n", len);
	disp("shared", shared2, len);

	// ���㹲����Կ��
	EC_POINT *point_shared = EC_POINT_new(group);
	nRet = EC_POINT_mul(group, point_shared, NULL, point_pub, bn_prikey2, ctx);
	if (1 == nRet)
	{
		nRet = EC_POINT_get_affine_coordinates_GFp(group, point_shared, bn_x, bn_y, ctx);
		if (1 == nRet)
		{
			printf("hex shared_x: ");
			bn_hex_printf(bn_x);
			printf("hex shared_y: ");
			bn_hex_printf(bn_y);
			printf("\n");
		}
	}

	EC_POINT *point_shared2 = EC_POINT_new(group);
	nRet = EC_POINT_mul(group, point_shared2, NULL, point_pub2, bn_prikey, ctx);
	if (1 == nRet)
	{
		nRet = EC_POINT_get_affine_coordinates_GFp(group, point_shared2, bn_x, bn_y, ctx);
		if (1 == nRet)
		{
			printf("hex shared2_x: ");
			bn_hex_printf(bn_x);
			printf("hex shared2_y: ");
			bn_hex_printf(bn_y);
			printf("\n");
		}
	}

	// ִ��ECDHͨ��ӳ��
	unsigned char s[] = "3F00C4D39D153F2B2A214A078D899B22";
	BIGNUM *bn_s = BN_new();
	nRet = BN_hex2bn(&bn_s, (char *)s);
	printf("hex s: 0x%s\n", s);
	printf("dec s: ");
	bn_dec_printf(bn_s);
	printf("hex s: ");
	bn_hex_printf(bn_s);
	printf("\n");

	BIGNUM *bn_one = BN_new();
	BN_one(bn_one);
	printf("dec bn_one: ");
	bn_dec_printf(bn_one);
	printf("hex bn_one: ");
	bn_hex_printf(bn_one);
	printf("\n");

	EC_POINT *G_map = EC_POINT_new(group);
	nRet = EC_POINT_mul(group, G_map, bn_s, point_shared, bn_one, ctx);
	if (1 == nRet)
	{
		nRet = EC_POINT_get_affine_coordinates_GFp(group, G_map, bn_x, bn_y, ctx);
		if (1 == nRet)
		{
			printf("hex G_map_x: ");
			bn_hex_printf(bn_x);
			printf("hex G_map_y: ");
			bn_hex_printf(bn_y);
			printf("\n");
		}
	}


	BN_free(bn_prikey);
	BN_free(bn_prikey2);
	BN_free(bn_x);
	BN_free(bn_y);
	BN_free(bn_s);

	BN_free(const_cast<BIGNUM *>(getprikey));
	BN_free(const_cast<BIGNUM *>(getprikey2));

	EC_GROUP_free(const_cast<EC_GROUP *>(group));
	EC_GROUP_free(const_cast<EC_GROUP *>(group1));

	EC_POINT_free(point_pub);
	EC_POINT_free(const_cast<EC_POINT *>(getpubkey));
	EC_POINT_free(point_pub2);
	EC_POINT_free(const_cast<EC_POINT *>(getpubkey2));
	EC_POINT_free(point_shared);
	EC_POINT_free(point_shared2);
	EC_POINT_free(G_map);

	//EC_KEY_free(ecdh);
	//EC_KEY_free(ecdh2);

	BN_CTX_free(ctx);
}

void anonymous_ECDH()
{
	int nRet = 0, len = 0;

	BN_CTX *ctx = NULL;
	if (NULL == (ctx = BN_CTX_new()))
		handleErrors();

	unsigned char prikey[] = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";
	unsigned char prikey2[] = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";

	// ����ָ����˽Կ����ʾ
	BIGNUM *bn_prikey, *bn_prikey2;
	bn_prikey = BN_new();
	nRet = BN_hex2bn(&bn_prikey, (char *)prikey);
	printf("hex prikey: 0x%s\n", prikey);
	printf("dec prikey: ");
	bn_dec_printf(bn_prikey);
	printf("hex prikey: ");
	bn_hex_printf(bn_prikey);
	printf("\n");

	bn_prikey2 = BN_new();
	nRet = BN_hex2bn(&bn_prikey2, (char *)prikey2);
	printf("hex prikey2: 0x%s\n", prikey2);
	printf("dec prikey2: ");
	bn_dec_printf(bn_prikey2);
	printf("hex prikey2: ");
	bn_hex_printf(bn_prikey2);
	printf("\n");

	const char *p = "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377";
	const char *a = "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9";
	const char *b = "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6";
	const char *x = "8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2";
	const char *y = "8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522";
	const char *order = "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7";
	const char *cofactor = "1";

	const EC_GROUP *group = create_curve(p, a ,b, order, x, y);
	nRet = EC_GROUP_check(group, ctx);
	GetCurveParam(group);

	EC_KEY *ecdh = EC_KEY_new();
	nRet = EC_KEY_set_group(ecdh, group);
	nRet = EC_KEY_set_private_key(ecdh, bn_prikey);

	// ��ȡEC_KEY�е���Բ����group1���������洴��group�ıȽ�
	const EC_GROUP *group1 = EC_KEY_get0_group(ecdh);
	nRet = EC_GROUP_cmp(group, group1, ctx);

	// ��Բ���ߵĵ�˼��㣬��generator(group)��˽Կbn_prikey��˵õ���Կpoint_pub
	EC_POINT *point_pub = EC_POINT_new(group);
	nRet = EC_POINT_mul(group, point_pub, bn_prikey, NULL, NULL, ctx);

	// �����Կx,y����
	BIGNUM *bn_x, *bn_y;
	bn_x = BN_new();
	bn_y = BN_new();
	nRet = EC_POINT_get_affine_coordinates_GFp(group, point_pub, bn_x, bn_y, ctx);
	if (1 == nRet)
	{
		printf("hex pub_x: ");
		bn_hex_printf(bn_x);
		printf("hex pub_y: ");
		bn_hex_printf(bn_y);
		printf("\n");
	}
	nRet = EC_KEY_set_public_key(ecdh, point_pub);

	const BIGNUM *getprikey = EC_KEY_get0_private_key(ecdh);			// ��ȡ˽Կ�����
	printf("hex prikey: ");
	bn_hex_printf(const_cast<BIGNUM *>(getprikey));
	printf("\n");
	const EC_POINT *getpubkey = EC_KEY_get0_public_key(ecdh);	// ��ȡ��Կ���жϺͼ�����Ƿ�һ��
	nRet = EC_POINT_cmp(group, point_pub, getpubkey, ctx);
	if (0 == nRet)
		printf("points are equal\n\n");


	EC_KEY *ecdh2 = EC_KEY_new();
	nRet = EC_KEY_set_group(ecdh2, group);
	nRet = EC_KEY_set_private_key(ecdh2, bn_prikey2);

	// ��Բ���ߵĵ�˼��㣬��generator(group)��˽Կbn_prikey2��˵õ���Կpoint_pub2
	EC_POINT *point_pub2 = EC_POINT_new(group);
	nRet = EC_POINT_mul(group, point_pub2, bn_prikey2, NULL, NULL, ctx);

	// �����Կx,y����
	nRet = EC_POINT_get_affine_coordinates_GFp(group, point_pub2, bn_x, bn_y, ctx);
	if (1 == nRet)
	{
		printf("hex pub2_x: ");
		bn_hex_printf(bn_x);
		printf("hex pub2_y: ");
		bn_hex_printf(bn_y);
		printf("\n");
	}
	nRet = EC_KEY_set_public_key(ecdh2, point_pub2);

	const BIGNUM *getprikey2 = EC_KEY_get0_private_key(ecdh2);
	printf("hex prikey2: ");
	bn_hex_printf(const_cast<BIGNUM *>(getprikey2));
	printf("\n");
	const EC_POINT *getpubkey2 = EC_KEY_get0_public_key(ecdh2);
	nRet = EC_POINT_cmp(group, point_pub2, getpubkey2, ctx);
	if (0 == nRet)
		printf("points are equal\n\n");

	// ���㹲����Կ��
	EC_POINT *point_shared = EC_POINT_new(group);
	nRet = EC_POINT_mul(group, point_shared, NULL, point_pub, bn_prikey2, ctx);
	if (1 == nRet)
	{
		nRet = EC_POINT_get_affine_coordinates_GFp(group, point_shared, bn_x, bn_y, ctx);
		if (1 == nRet)
		{
			printf("hex shared_x: ");
			bn_hex_printf(bn_x);
			printf("hex shared_y: ");
			bn_hex_printf(bn_y);
			printf("\n");
		}
	}

	EC_POINT *point_shared2 = EC_POINT_new(group);
	nRet = EC_POINT_mul(group, point_shared2, NULL, point_pub2, bn_prikey, ctx);
	if (1 == nRet)
	{
		nRet = EC_POINT_get_affine_coordinates_GFp(group, point_shared2, bn_x, bn_y, ctx);
		if (1 == nRet)
		{
			printf("hex shared2_x: ");
			bn_hex_printf(bn_x);
			printf("hex shared2_y: ");
			bn_hex_printf(bn_y);
			printf("\n");
		}
	}


	BN_free(bn_prikey);
	BN_free(bn_prikey2);
	BN_free(bn_x);
	BN_free(bn_y);
	BN_free(const_cast<BIGNUM *>(getprikey));
	BN_free(const_cast<BIGNUM *>(getprikey2));

	EC_GROUP_free(const_cast<EC_GROUP *>(group));
	EC_GROUP_free(const_cast<EC_GROUP *>(group1));

	EC_POINT_free(point_pub);
	EC_POINT_free(point_pub2);
	EC_POINT_free(const_cast<EC_POINT *>(getpubkey));
	EC_POINT_free(const_cast<EC_POINT *>(getpubkey2));
	EC_POINT_free(point_shared);
	EC_POINT_free(point_shared2);

	BN_CTX_free(ctx);
}

void test()
{
	//EC_GROUP *group = create_curve();
	//if (NULL != group)
	//	GetCurveParam(group);

	//testECDH();

	//testECDH_selfCurve();

	anonymous_ECDH();
}
