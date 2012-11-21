#include <string.h>
#include <stdio.h>
#include "scipher.h"

/*
   initialize the cipher with key k and iv; ctx is the state.
 */
void init(unsigned char *k, unsigned char *iv, sctx *ctx)
{
      memset(ctx->s,0,40); // setting the bits in the s array to 0
      memcpy((char*)(ctx->s) +  18,iv,10);   // copying iv to the s array
      
      *((unsigned char*) (&ctx->s[0]) + 4) |= 0b00000111 ;  // adding 111 to the bits 286,287 and 288
     
      unsigned char MSB_3bits=0,t1=0,t2=0,t3=0;   //declaration of bytes used
      MSB_3bits = (* ((unsigned char*)&(ctx->s[2]) +7) ) & 0b11100000; // Obtaining the most significant 3 bits of the byte and storing it in MSB_3bits
      MSB_3bits = MSB_3bits >> 5; // Right shift MSB_3bits 5 times

      // shift s[2] left 3 bits
      ctx->s[2]=ctx->s[2]<<3; 
                             
      ctx->s[3]=ctx->s[3]<<3;  // shift s[3] left 3 bits
      *((unsigned char*)(&ctx->s[3])  +  0 )   |=   MSB_3bits; // Adding the most significant bits obtained in MSB_3bits to s[3]

      // copy the key value
      memcpy(((unsigned char*)(&ctx->s[3])+6),k,10);

      int i; 
      unsigned char reserve1=0,reserve2=0,reserve3=0,reserve4=0;
      unsigned char s66=0,s91=0,s92=0,s93=0,s171=0,s162=0,s175=0,s176=0,s177=0,s264=0,s243=0,s286=0,s287=0,s288=0,s69=0;
      for(i=0;i<4*288;i++) // iv and key generation
      {                    // calculation of the particular bits for calculating t1 t2 and t3     
      s66 = (*((unsigned char*)(&ctx->s[3]) +7)) & 0b01000000; // obtaining the 7th bit of 7th byte of s[3] by making an AND to it 
      s66 >>=6; // making a right shift to bring the value to the LSB
      s91 = (*((unsigned char*)(&ctx->s[3]) +4)) & 0b00100000; // obtaining the 6th bit of 4th byte of s[3] by making an AND to it
      s91 >>=5; // making right shifts to bring the value to LSB
      s92 = (*((unsigned char*)(&ctx->s[3])+4)) & 0b00010000; // obtaining the 5th bit of 4th byte of s[3] by making an AND to it
      s92 >>=4; // making right shifts to bring the value to LSB
      s93 = (*((unsigned char*)(&ctx->s[3])+4)) & 0b00001000; // obtaining the 4th bit of 4th byte of s[3] by making an AND to it
      s93 >>=3; // making right shifts to bring the value to LSB
      s171 = (*((unsigned char*)(&ctx->s[2])+2)) & 0b00100000; // obtaining the 6th bit of 2nd byte of s[2] by making an AND to it
      s171 >>=5; // making right shifts to bring the value to LSB

      t1 = s66 ^ (s91 & s92) ^ s93 ^ s171; // calculation of t1

      s162 = (*((unsigned char*)(&ctx->s[2])+3)) & 0b01000000; // the calculation of bits is done as explained above by making an AND operation to obtain the bit
      s162 >>=6;
      s175 = (*((unsigned char*)(&ctx->s[2])+2)) & 0b00000010;
      s175 >>=1;
      s176 = (*((unsigned char*)(&ctx->s[2])+2)) & 0b00000001;
      s177 = (*((unsigned char*)(&ctx->s[2])+1)) & 0b10000000;
      s177 >>=7;
      s264 = (*((unsigned char*)(&ctx->s[0])+7)) & 0b00000001;

      t2 = s162 ^ (s175 & s176) ^ s177 ^ s264; // calculation of t2

      s243 = (*((unsigned char*)(&ctx->s[1])+1)) & 0b00100000;
      s243 >>=5;
      s286 = (*((unsigned char*)(&ctx->s[0])+4)) & 0b00000100;
      s286 >>=2;
      s287 = (*((unsigned char*)(&ctx->s[0])+4)) & 0b00000010;
      s287 >>=1;
      s288 = (*((unsigned char*)(&ctx->s[0])+4)) & 0b00000001;
      s69 = (*((unsigned char*)(&ctx->s[3])+7)) & 0b00001000;
      s69 >>=3;

      t3 = s243 ^ (s286 & s287) ^ s288 ^ s69; // calculation of t3

      //shifting by one bit the whole s array and replacing the respective bits
      reserve1 = (*((unsigned char*)(&ctx->s[4])+0)) & 0b00000001; // Obtaining the bits in the 1st bit of the 1st byte in array s by performing AND operation ,                                                                           //  in order to replace them later.   
      reserve1<<=7;                                                //  after shifting of the byte is done
      reserve2 = (*((unsigned char*)(&ctx->s[3])+0)) & 0b00000001;
      reserve2<<=7;
      reserve3 = (*((unsigned char*)(&ctx->s[2])+0)) & 0b00000001;
      reserve3<<=7;
      reserve4 = (*((unsigned char*)(&ctx->s[1])+0)) & 0b00000001;
      reserve4<<=7;
      ctx->s[0] >>=1; // shifting of the whole block
      ctx->s[1] >>=1;
      ctx->s[2] >>=1;
      ctx->s[3] >>=1;
      ctx->s[4] >>=1;
      t3<<=7;
      t2<<=6;
      t1<<=2;
      
          *(((unsigned char*)(&ctx->s[3])+7)) &= 0b01111111; // replacing the bits, by the bits stored before the shifting operation by finding it using AND operation
          *(((unsigned char*)(&ctx->s[3])+7))  |= reserve1;  // and replacing it using OR operation

          *(((unsigned char*)(&ctx->s[2])+7)) &= 0b01111111;
          *(((unsigned char*)(&ctx->s[2])+7)) |= reserve2;

          *(((unsigned char*)(&ctx->s[1])+7)) &= 0b01111111;
          *(((unsigned char*)(&ctx->s[1])+7))  |= reserve3;
          
	  *(((unsigned char*)(&ctx->s[0])+7)) &= 0b01111111;
          *(((unsigned char*)(&ctx->s[0])+7))  |= reserve4;
         
          *(((unsigned char*)(&ctx->s[4])+7)) &= 0b01111111;
          *(((unsigned char*)(&ctx->s[4])+7))  |= t3;
         
          *(((unsigned char*)(&ctx->s[3])+4)) &= 0b11111011; 
          *(((unsigned char*)(&ctx->s[3])+4))  |= t1;
          
          *(((unsigned char*)(&ctx->s[2])+1)) &= 0b10111111;
          *(((unsigned char*)(&ctx->s[2])+1))  |= t2;

      }
}


/*
   encrypt/decrypt message m of length len into buffer b.
 */
void crypt(unsigned char *b, unsigned char *m, int len, sctx *ctx) {

      unsigned char z =0;
      unsigned char t1=0,t2=0,t3=0;
      int i;
      unsigned char reserve1=0,reserve2=0,reserve3=0,reserve4=0;
      unsigned char s66=0,s91=0,s92=0,s93=0,s171=0,s162=0,s175=0,s176=0,s177=0,s264=0,s243=0,s286=0,s287=0,s288=0,s69=0;
      for(i=0;i<len*8;i++) //keystream generation
      { // calculation of the particular bits needed for calculating t1 t2 and t3 
      s66 = (*((unsigned char*)(&ctx->s[3]) +7)) & 0b01000000; // calculation of the bits needed is done by doing an AND operation and is shifted to the LSB 
      s66 >>=6;
      s91 = (*((unsigned char*)(&ctx->s[3]) +4)) & 0b00100000;
      s91 >>=5;
      s92 = (*((unsigned char*)(&ctx->s[3])+4)) & 0b00010000;
      s92 >>=4;
      s93 = (*((unsigned char*)(&ctx->s[3])+4)) & 0b00001000;
      s93 >>=3;
      s171 = (*((unsigned char*)(&ctx->s[2])+2)) & 0b00100000;
      s171 >>=5;

      t1 = s66 ^ s93 ; // calculation of t1

      s162 = (*((unsigned char*)(&ctx->s[2])+3)) & 0b01000000;
      s162 >>=6;
      s175 = (*((unsigned char*)(&ctx->s[2])+2)) & 0b00000010;
      s175 >>=1;
      s176 = (*((unsigned char*)(&ctx->s[2])+2)) & 0b00000001;
      s177 = (*((unsigned char*)(&ctx->s[2])+1)) & 0b10000000;
      s177 >>=7;
      s264 = (*((unsigned char*)(&ctx->s[0])+7)) & 0b00000001;

      t2 = s162 ^ s177 ; // calculation of t2

      s243 = (*((unsigned char*)(&ctx->s[1])+1)) & 0b00100000;
      s243 >>=5;
      s286 = (*((unsigned char*)(&ctx->s[0])+4)) & 0b00000100;
      s286 >>=2;
      s287 = (*((unsigned char*)(&ctx->s[0])+4)) & 0b00000010;
      s287 >>=1;
      s288 = (*((unsigned char*)(&ctx->s[0])+4)) & 0b00000001;
      s69 = (*((unsigned char*)(&ctx->s[3])+7)) & 0b00001000;
      s69 >>=3;

      t3 = s243 ^ s288 ; //calculation of t3

      
      z |= (t1 ^ t2 ^t3)<<(i%8); // calculation of the keystream z
      // store bit into a byte
      if ((i+1)%8 == 0)
      {
         b[i/8] = m[i/8] ^ z;
         z=0;
      }

      t1 = t1 ^ (s91 & s92)   ^ s171;
      t2 = t2 ^ (s175 & s176) ^ s264;
      t3 = t3 ^ (s286 & s287) ^ s69;
      //shifting by one bit the whole s array and replacing the respective bits
      reserve1 = (*((unsigned char*)(&ctx->s[4])+0)) & 0b00000001; // calculation of the bits needed by setting the particular bit to 1 by AND operation and shifting it
      reserve1<<=7;
      reserve2 = (*((unsigned char*)(&ctx->s[3])+0)) & 0b00000001;
      reserve2<<=7;
      reserve3 = (*((unsigned char*)(&ctx->s[2])+0)) & 0b00000001;
      reserve3<<=7;
      reserve4 = (*((unsigned char*)(&ctx->s[1])+0)) & 0b00000001;
      reserve4<<=7;
      ctx->s[0] >>=1; // shifting operation is done
      ctx->s[1] >>=1;
      ctx->s[2] >>=1;
      ctx->s[3] >>=1;
      ctx->s[4] >>=1;
      t3<<=7;
      t2<<=6;
      t1<<=2;
      
          *(((unsigned char*)(&ctx->s[3])+7)) &= 0b01111111; //replacing the particular bits after shifting operation by finding the bits and doing an OR operation
          *(((unsigned char*)(&ctx->s[3])+7))  |= reserve1;

          *(((unsigned char*)(&ctx->s[2])+7)) &= 0b01111111;
          *(((unsigned char*)(&ctx->s[2])+7)) |= reserve2;

          *(((unsigned char*)(&ctx->s[1])+7)) &= 0b01111111;
          *(((unsigned char*)(&ctx->s[1])+7))  |= reserve3;
          
	  *(((unsigned char*)(&ctx->s[0])+7)) &= 0b01111111;
          *(((unsigned char*)(&ctx->s[0])+7))  |= reserve4;
         
          *(((unsigned char*)(&ctx->s[4])+7)) &= 0b01111111;
          *(((unsigned char*)(&ctx->s[4])+7))  |= t3;
         
          *(((unsigned char*)(&ctx->s[3])+4)) &= 0b11111011; 
          *(((unsigned char*)(&ctx->s[3])+4))  |= t1;
          
          *(((unsigned char*)(&ctx->s[2])+1)) &= 0b10111111;
          *(((unsigned char*)(&ctx->s[2])+1))  |= t2;

      }
}

