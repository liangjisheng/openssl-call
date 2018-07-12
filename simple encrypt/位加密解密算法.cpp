#include"stdio.h"
#include"stdlib.h"
#include"string.h"
//bitcode
char *bitcode(char *str,int n)
{
	char *wen;
	int i=0,len;
	len=strlen(str);
	wen=(char*)malloc(len+1);
	while(i<len){wen[i]=str[i]^n;i++;}
	wen[i]='\0';
	return wen;
}
//main
void main()
{
	char ch,str[100],*miwen,*mingwen,again;
	printf("位加密解密算法演示.\n");
s1:printf("输入加密密钥:");
   fflush(stdin);
   scanf("%c",&ch);
   printf("输入明文:");
   fflush(stdin);
   gets(str);
   miwen=bitcode(str,ch);
   printf("加密密文为:%s\n",miwen);
   mingwen=bitcode(miwen,ch);
   printf("解密明文为:%s\n",mingwen);
s2:printf("继续执行(y/n)?");
   fflush(stdin);
   scanf("%c",&again);
   if(again=='y'||again=='Y')goto s1;
   else if(again=='n'||again=='N')goto s3;
   else{printf("输入错误,重新输入.\n");goto s2;}
s3:printf("演示结束.\n");
}