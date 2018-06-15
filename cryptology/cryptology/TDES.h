//---------------------------------------------------------------------------
#ifndef _TDESH
#define _TDESH
//---------------------------------------------------------------------------
class TDES
{
  public:
         TDES(); //类构造函数
        ~TDES(); //类析构函数
        //--------------------------------------------------------------
		void des_3(unsigned char *d,unsigned char *e,unsigned char *f,unsigned char mode);
        void key_schedule(unsigned char key[], unsigned char schedule[][6], unsigned int mode);
  private:
		void IP(unsigned int state[], unsigned char in[]);
		void InvIP(unsigned int state[], unsigned char in[]);
		unsigned int f(unsigned int state, unsigned char key[]);
		void des_crypt(unsigned char in[], unsigned char out[], unsigned char key[][6]);
		void three_des_key_schedule(unsigned char key[], unsigned char schedule[][16][6], unsigned int mode);
		void three_des_crypt(unsigned char in[], unsigned char out[], unsigned char key[][16][6]);
};
//---------------------------------------------------------------------------
#endif