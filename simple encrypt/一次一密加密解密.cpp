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
	printf("һ��һ�ܼ����㷨.\n");
s1:
	printf("��������:");
	fflush(stdin);
	gets(str);
	len=strlen(str);
	while(i<len){key[i]=rand()%10+'0';i++;}//������Կ����
	printf("�˴μ�����Կ����Ϊ:%s\n",key);
	//for(i=0;i<len;i++)printf("%c",key[i]);
	miwen=bitcode(str);
	printf("��������Ϊ:%s\n",miwen);
	mingwen=bitcode(miwen);
	printf("��������Ϊ:%s\n",mingwen);
s2:
	printf("����ִ��(y/n)?");
	fflush(stdin);
	scanf("%c",&again);
	if(again=='y'||again=='Y')goto s1;
	else if(again=='n'||again=='N')goto s3;
	else {printf("���������������.\n");goto s2;}
s3:
	printf("��ʾ����.\n");
}