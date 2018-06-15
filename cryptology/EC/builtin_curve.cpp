
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl\ec.h>

void test_builtin_curves()
{
	EC_builtin_curve *curves = NULL;
	size_t crv_len = 0, n = 0;
	int nid, ret;
	EC_GROUP *group = NULL;

	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = (EC_builtin_curve *)OPENSSL_malloc(sizeof(EC_builtin_curve) * crv_len);
	EC_get_builtin_curves(curves, crv_len);

	for (n = 0; n < crv_len; ++n)
	{
		nid = curves[n].nid;
		group = NULL;
		group = EC_GROUP_new_by_curve_name(nid);
		ret = EC_GROUP_check(group, NULL);
	}

	OPENSSL_free(curves);
}