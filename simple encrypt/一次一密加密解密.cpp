#include"stdio.h"
#include"stdlib.h"
#include"string.h"
#include"time.h"
#define max 100
char key[max];
int len;
//bitcode
char *bitcode(char *str)
{
	int i=0;
	char *wen;
	wen=(char*)malloc(len+1);
	while(i<len){wen[i]=str[i]^key[i];i++;}
	wen[i]='\0';
	return wen;
}
//main
void main()
{
	char again,*miwen,*mingwen,str[max];
	int i=0;
	srand(time(NULL));
	printf("一次一密加密算法.\n");
s1:
	printf("输入明文:");
	fflush(stdin);
	gets(str);
	len=strlen(str);
	while(i<len){key[i]=rand()%10+'0';i++;}//产生密钥序列
	printf("此次加密密钥序列为:%s\n",key);
	//for(i=0;i<len;i++)printf("%c",key[i]);
	miwen=bitcode(str);
	printf("加密密文为:%s\n",miwen);
	mingwen=bitcode(miwen);
	printf("解密明文为:%s\n",mingwen);
s2:
	printf("继续执行(y/n)?");
	fflush(stdin);
	scanf("%c",&again);
	if(again=='y'||again=='Y')goto s1;
	else if(again=='n'||again=='N')goto s3;
	else {printf("输入错误，重新输入.\n");goto s2;}
s3:
	printf("演示结束.\n");
}