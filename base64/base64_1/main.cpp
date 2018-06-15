
#include <iostream>
#include <vector>
#include <fstream>
#include <string.h>
#include "ZBase64.h"

#include <opencv2/opencv.hpp>

using std::cout;
using std::endl;
using std::cerr;
using std::ifstream;
using std::ofstream;
using std::vector;

using namespace cv;


void test_image_cv()
{
	Mat img = imread("test.jpg");
	vector<unsigned char> vecImg;
	vector<int> vecCompression_params;
	vecCompression_params.push_back(CV_IMWRITE_JPEG_QUALITY);
	vecCompression_params.push_back(90);
	imencode(".jpg", img, vecImg, vecCompression_params);

	ZBase64 base64;
	string imgbase64 = base64.Encode(vecImg.data(), vecImg.size());
	// cout << imgbase64 << endl;
	ofstream outstream("test.txt", std::ios_base::out | std::ios_base::binary);
	if(!outstream.is_open())
	{
		cerr << "open output file failed" << endl;
		exit(-1);
	}
	outstream.write(imgbase64.c_str(), imgbase64.size());
	outstream.close();
}

void test_string()
{
	// 测试字符串是，转码和解码都没有问题，说明下面转换图片是，读写文件应该是有问题
	ZBase64 base64;
	string str = "test";
	string str_encode = base64.Encode((unsigned char*)str.c_str(), str.size());
	cout << str << endl;
	cout << "encode : " << str_encode << ", size = " << str_encode.size() << endl;
	int nDecodeLen = 0;
	string str_decode = base64.Decode(str_encode.c_str(), str_encode.size(), nDecodeLen);
	cout << "decode : " << str_decode << ", size = " << str_decode.size() << endl;
	cout << "decode length = " << nDecodeLen << endl;
}

void test_image_encode()
{
	string strFileName = "test.jpg";
	string strFileName_encode = "test.txt";
	string strFileName_decode = "test_decode.jpg";

	ifstream instream(strFileName.c_str(), 
		std::ios_base::in | std::ios::binary);
	if(!instream.is_open())
	{
		cerr << "open input file failed" << endl;
		exit(-1);
	}

	ofstream outstream(strFileName_encode.c_str(), 
		std::ios_base::out | std::ios::binary);
	if(!outstream.is_open())
	{
		cerr << "open output file failed" << endl;
		exit(-1);
	}

	ZBase64 base64;
	const int nLen = 999;
	char *p = new char[nLen];
	memset(p, 0, nLen);
	
	// eof: end of file，文件到达末尾的标识
	while(!instream.eof())
	{
		instream.read(p, nLen);
		unsigned char tmp[nLen] = {0};
		memcpy(tmp, p, nLen);
		// int nReadLen1 = strlen(p);			// strlen()遇到\0就会结束，有时候会不准
		int nReadLen = instream.gcount();		// 获取读取的字符的个数
		string strEncode = base64.Encode(tmp, nReadLen);
		outstream.write(strEncode.c_str(), strEncode.size());
		memset(p, 0, nLen);
		if(999 != nReadLen)
		{
			cout << "end of file" << endl;
			break;
		}
	}

	instream.close();
	outstream.close();
	delete []p;
	p = NULL;
}

void test_image_decode()
{
	string strFileName_encode = "test.txt";
	string strFileName_decode = "test_decode.jpg";

	ifstream instream(strFileName_encode.c_str(), 
		std::ios_base::in | std::ios_base::binary);
	if(!instream.is_open())
	{
		cerr << "open input file failed" << endl;
		exit(-1);
	}

	ofstream outstream(strFileName_decode.c_str(), 
		std::ios_base::out | std::ios_base::binary);
	if(!outstream.is_open())
	{
		cerr << "open output file failed" << endl;
		exit(-1);
	}

	ZBase64 base64;
	const int nLen = 999;
	char *p = new char[nLen];
	memset(p, 0, nLen);

	// eof: end of file，文件到达末尾的标识
	while(!instream.eof())
	{
		instream.read(p, nLen);
		int nReadLen = instream.gcount();		// 获取读取的字节的个数
		int nDecodeLen = 0;
		string strDecode = base64.Decode(p, nReadLen, nDecodeLen);
		outstream.write(strDecode.c_str(), strDecode.size());
		memset(p, 0, nLen);
	}

	instream.close();
	outstream.close();
	delete []p;
	p = NULL;
}


int main()
{
	test_string();
	// test_image_encode();
	// test_image_decode();

	system("pause");
	return 0;
}

