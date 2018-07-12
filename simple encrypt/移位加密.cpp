//某个公司采用公用电话传递数据，数据是四位的整数，在传递过程中是加密的，加密规则如下：
//每位数字都加上5,然后用和除以10的余数代替该数字，再将第一位和第四位交换，第二位和第三位交换。
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
	cout<<"输出加密后的数字:";
	for(i=0;i<4;i++)
		cout<<a[i];
	cout<<endl;
	return 0;
}