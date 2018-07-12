#include"stdio.h"
#include"stdlib.h"
#include"string.h"
//jiami
char *jiami(char *str,int n)
{
	char *miwen;
	int i=0,len;
	len=strlen(str);
	miwen=(char*)malloc(len+1);
	//for(i=0;i<len;i++)miwen[i]=str[i]+n;
	while(i<len){miwen[i]=str[i]+n;i++;}
	miwen[len]='\0';
	return miwen;
}
//jiemi
char *jiemi(char *str,int n)
{
	char *mingwen;
	int i=0,len;
	len=strlen(str);
	mingwen=(char*)malloc(len+1);
	while(i<len){mingwen[i]=str[i]-n;i++;}
	mingwen[len]='\0';
	return mingwen;
}
//main
void main()
{
	int n;
	char *miwen,str[100],again;
	printf("替换加密解密算法.\n");
s1:printf("输入加密用的密钥:");
   scanf("%d",&n);
   printf("输入明文:");
   fflush(stdin);
   gets(str);
   miwen=jiami(str,n);
   printf("加密后的密文为:%s\n",miwen);
   miwen=jiemi(miwen,n);
   printf("解密后的明文为:%s\n",miwen);
s2:printf("继续执行(y/n)?");
   fflush(stdin);
   scanf("%c",&again);
   if(again=='y'||again=='Y')goto s1;
   else if(again=='n'||again=='N')goto s3;
   else {printf("输入错误,重新输入.\n");goto s2;}
s3:printf("演示结束.\n");
}