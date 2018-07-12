#include"stdio.h"
#include"stdlib.h"
#include"string.h"
//jiami
char *jiami(char *str,int n)
{
	int i,j,k,d,len;
	char *temp,*miwen,*mtemp;
	len=strlen(str);
	if((d=len%n)!=0)len=len+n-d;
	temp=(char*)malloc(len+1);
	miwen=(char*)malloc(len+1);
	mtemp=miwen;
	strcpy(temp,str);
	for(i=strlen(str);i<len;i++)temp[i]=32;
	for(k=0;k<n;k++)
		for(j=0;j<len/n;j++)
		{*mtemp=temp[k+j*n];mtemp++;}
	*mtemp='\0';
	free(temp);
	return miwen;  //返回密文
}
//jiemi
char *jiemi(char *str,int n)
{
	int i,j,k,d,len;
	char *temp,*mingwen,*mtemp;
	len=strlen(str);
	if((d=len%n)!=0)len=len+n-d;
	n=len/n;
	temp=(char*)malloc(len+1);
	mingwen=(char*)malloc(len+1);
	mtemp=mingwen;
	strcpy(temp,str);
	for(i=strlen(str);i<len;i++)temp[i]=32;
	temp[len]='\0';
	for(k=0;k<n;k++)
		for(j=0;j<len/n;j++)
		{*mtemp=temp[k+j*n];mtemp++;}
	while(*(--mtemp)==32);//啥意思？
	mtemp++;*mtemp='\0';
	return mingwen;
}
//main
void main()
{
	int n;
	char str[100],*miwen,again;
	printf("换位加密解密算法演示.\n");
s1:printf("输入加密矩阵每行的字符数:");
   scanf("%d",&n);
   printf("输入明文:");
   fflush(stdin);
   gets(str);
   miwen=jiami(str,n);
   printf("加密密文为:%s\n",miwen);
   miwen=jiemi(miwen,n);
   printf("解密明文为:%s\n",miwen);
s2:printf("继续执行(y/n)?");
   fflush(stdin);
   scanf("%c",&again);
   if(again=='y'||again=='Y')goto s1;
   else if(again=='n'||again=='N')goto s3;
   else {printf("输入错误，重新输入.\n");goto s2;}
s3:printf("演示结束.\n");
}