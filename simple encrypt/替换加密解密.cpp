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
	printf("�滻���ܽ����㷨.\n");
s1:printf("��������õ���Կ:");
   scanf("%d",&n);
   printf("��������:");
   fflush(stdin);
   gets(str);
   miwen=jiami(str,n);
   printf("���ܺ������Ϊ:%s\n",miwen);
   miwen=jiemi(miwen,n);
   printf("���ܺ������Ϊ:%s\n",miwen);
s2:printf("����ִ��(y/n)?");
   fflush(stdin);
   scanf("%c",&again);
   if(again=='y'||again=='Y')goto s1;
   else if(again=='n'||again=='N')goto s3;
   else {printf("�������,��������.\n");goto s2;}
s3:printf("��ʾ����.\n");
}