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
	printf("λ���ܽ����㷨��ʾ.\n");
s1:printf("���������Կ:");
   fflush(stdin);
   scanf("%c",&ch);
   printf("��������:");
   fflush(stdin);
   gets(str);
   miwen=bitcode(str,ch);
   printf("��������Ϊ:%s\n",miwen);
   mingwen=bitcode(miwen,ch);
   printf("��������Ϊ:%s\n",mingwen);
s2:printf("����ִ��(y/n)?");
   fflush(stdin);
   scanf("%c",&again);
   if(again=='y'||again=='Y')goto s1;
   else if(again=='n'||again=='N')goto s3;
   else{printf("�������,��������.\n");goto s2;}
s3:printf("��ʾ����.\n");
}