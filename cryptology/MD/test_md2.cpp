
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/e_os.h"

//#ifdef OPENSSL_NO_MD2
//int main(int argc, char *argv[])
//{
//    printf("No MD2 support\n");
//    return (0);
//}
//#else
# include <openssl/evp.h>
# include <openssl/mdc2.h>

# ifdef CHARSET_EBCDIC
#  include <openssl/ebcdic.h>
# endif

static char *test[] = 
{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    NULL,
};

static char *ret[] = {
    "8350e5a3e24c153df2275c9f80692773",
    "32ec01ec4a6dac72c0ab96fb34c0b5d1",
    "da853b0d3f88d99b30283a69e6ded6bb",
    "ab4f496bfb2a530b219ff33031fe06b0",
    "4e8ddff3650292ab5a4108c3aa47940b",
    "da33def2a42df13975352846c30338cd",
    "d5976f79d83d3a0dc9806c3c66f3efd8",
};

static char *pt(unsigned char *md);

int test_md2()
{
    int i, err = 0;
    char **P, **R;
    char *p;
    unsigned char md[MDC2_DIGEST_LENGTH];

    P = test;
    R = ret;
    i = 1;
    while (*P != NULL) 
	{
		EVP_Digest((unsigned char *)*P, strlen(*P), md, NULL, EVP_mdc2(), NULL);
        p = pt(md);
        if (strcmp(p, *R) != 0) {
            printf("error calculating MD2 on '%s'\n", *P);
            printf("got %s instead of %s\n", p, *R);
            err++;
        } else
            printf("test %d ok\n", i);
        i++;
        R++;
        P++;
    }
# ifdef OPENSSL_SYS_NETWARE
    if (err)
        printf("ERROR: %d\n", err);
# endif
    EXIT(err);
    return err;
}

static char *pt(unsigned char *md)
{
    int i;
    static char buf[80];

    for (i = 0; i < MDC2_DIGEST_LENGTH; i++)
        sprintf(&(buf[i * 2]), "%02x", md[i]);
    return (buf);
}
//#endif
