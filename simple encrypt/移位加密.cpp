//ĳ����˾���ù��õ绰�������ݣ���������λ���������ڴ��ݹ������Ǽ��ܵģ����ܹ������£�
//ÿλ���ֶ�����5,Ȼ���úͳ���10��������������֣��ٽ���һλ�͵���λ�������ڶ�λ�͵���λ������
#include"iostream"
using namespace std;
int main(int argc,char *argv[])
{
	int a[4],i,num;
	cout<<"input a numbers:";
	cin>>num;
	a[0]=num/1000;num=num%1000;
	a[1]=num/100;num=num%100;
	a[2]=num/10;num=num%10;
	a[3]=num;
	for(i=0;i<4;i++){
		a[i]+=5;
		a[i]=a[i]%10;
	}
	int temp;
	temp=a[0],a[0]=a[3],a[3]=temp;
	temp=a[1],a[1]=a[2],a[2]=temp;
	cout<<"������ܺ������:";
	for(i=0;i<4;i++)
		cout<<a[i];
	cout<<endl;
	return 0;
}