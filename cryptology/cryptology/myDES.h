
#ifndef __SELFDEFINE_DES_H__
#define __SELFDEFINE_DES_H__

#define EN0	0	// MODE == encrypt
#define DE1	1	// MODE == decrypt

typedef union 
{
	unsigned long blok[2];
	unsigned short word[4];
	unsigned char byte[8];
} M68K;

extern void des8(unsigned char *InData,unsigned char *key,unsigned char *OutData,short Mode,int readlen);
extern void des16(unsigned char *InData,unsigned char *key,unsigned char *OutData,short Mode,int readlen);

#endif  //__SELFDEFINE_DES_H__
