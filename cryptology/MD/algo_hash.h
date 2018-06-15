
#ifndef __ALGO_HASH_H__
#define __ALGO_HASH_H__

void HashInit();

int HashEncode(const char *algo, const char *input, unsigned int input_length, 
	unsigned char *output, unsigned int &output_length);

#endif  //__ALGO_HASH_H__