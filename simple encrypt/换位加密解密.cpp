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
	return miwen;  //��������
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
	while(*(--mtemp)==32);//ɶ��˼��
	mtemp++;*mtemp='\0';
	return mingwen;
}
//main
void main()
{
	int n;
	char str[100],*miwen,again;
	printf("��λ���ܽ����㷨��ʾ.\n");
s1:printf("������ܾ���ÿ�е��ַ���:");
   scanf("%d",&n);
   printf("��������:");
   fflush(stdin);
   gets(str);
   miwen=jiami(str,n);
   printf("��������Ϊ:%s\n",miwen);
   miwen=jiemi(miwen,n);
   printf("��������Ϊ:%s\n",miwen);
s2:printf("����ִ��(y/n)?");
   fflush(stdin);
   scanf("%c",&again);
   if(again=='y'||again=='Y')goto s1;
   else if(again=='n'||again=='N')goto s3;
   else {printf("���������������.\n");goto s2;}
s3:printf("��ʾ����.\n");
}