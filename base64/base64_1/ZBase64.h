
#include <string>

using std::string;

class ZBase64
{
public:
	string Encode(const unsigned char* data, int nDataByte);
	string Decode(const char* data, int nDataByte, int &nOutByte);
};