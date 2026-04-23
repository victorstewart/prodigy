#pragma once

#include <linux/types.h>

#include <ebpf/kernel/aes.tables.h>

#define GETU32(pt) (((__u32)(pt)[0] << 24) ^ ((__u32)(pt)[1] << 16) ^ ((__u32)(pt)[2] <<  8) ^ ((__u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (__u8)((st) >> 24); (ct)[1] = (__u8)((st) >> 16); (ct)[2] = (__u8)((st) >>  8); (ct)[3] = (__u8)(st); }

struct aes_decrypt_state {

   __u32 rk[44];
};

__attribute__((__always_inline__)) 
static void aesDecrypt(struct aes_decrypt_state *aes_state, const __u8 ct[16], __u8 pt[16]) 
{
   __u32 s0, s1, s2, s3, t0, t1, t2, t3;

   /*
    * map byte array block to cipher state
    * and add initial round key:
    */
   s0 = GETU32(ct     ) ^ aes_state->rk[0];
   s1 = GETU32(ct +  4) ^ aes_state->rk[1];
   s2 = GETU32(ct +  8) ^ aes_state->rk[2];
   s3 = GETU32(ct + 12) ^ aes_state->rk[3];

   /* round 1: */
   t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ aes_state->rk[ 4];
   t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ aes_state->rk[ 5];
   t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ aes_state->rk[ 6];
   t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ aes_state->rk[ 7];
   /* round 2: */
   s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ aes_state->rk[ 8];
   s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ aes_state->rk[ 9];
   s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ aes_state->rk[10];
   s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ aes_state->rk[11];
   /* round 3: */
   t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ aes_state->rk[12];
   t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ aes_state->rk[13];
   t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ aes_state->rk[14];
   t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ aes_state->rk[15];
   /* round 4: */
   s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ aes_state->rk[16];
   s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ aes_state->rk[17];
   s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ aes_state->rk[18];
   s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ aes_state->rk[19];
   /* round 5: */
   t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ aes_state->rk[20];
   t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ aes_state->rk[21];
   t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ aes_state->rk[22];
   t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ aes_state->rk[23];
   /* round 6: */
   s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ aes_state->rk[24];
   s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ aes_state->rk[25];
   s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ aes_state->rk[26];
   s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ aes_state->rk[27];
   /* round 7: */
   t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ aes_state->rk[28];
   t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ aes_state->rk[29];
   t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ aes_state->rk[30];
   t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ aes_state->rk[31];
   /* round 8: */
   s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ aes_state->rk[32];
   s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ aes_state->rk[33];
   s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ aes_state->rk[34];
   s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ aes_state->rk[35];
   /* round 9: */
   t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ aes_state->rk[36];
   t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ aes_state->rk[37];
   t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ aes_state->rk[38];
   t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ aes_state->rk[39];
   
   __u32 rk_shift = 10 << 2;

   /*
    * apply last round and
    * map cipher state to byte array block:
    */
   s0 =
      (Td4[(t0 >> 24)       ] & 0xff000000) ^
      (Td4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
      (Td4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
      (Td4[(t1      ) & 0xff] & 0x000000ff) ^
      aes_state->rk[rk_shift + 0];
   PUTU32(pt     , s0);
   s1 =
      (Td4[(t1 >> 24)       ] & 0xff000000) ^
      (Td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
      (Td4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
      (Td4[(t2      ) & 0xff] & 0x000000ff) ^
      aes_state->rk[rk_shift + 1];
   PUTU32(pt +  4, s1);
   s2 =
      (Td4[(t2 >> 24)       ] & 0xff000000) ^
      (Td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
      (Td4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
      (Td4[(t3      ) & 0xff] & 0x000000ff) ^
      aes_state->rk[rk_shift +2];
   PUTU32(pt +  8, s2);
   s3 =
      (Td4[(t3 >> 24)       ] & 0xff000000) ^
      (Td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
      (Td4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
      (Td4[(t0      ) & 0xff] & 0x000000ff) ^
      aes_state->rk[rk_shift + 3];
   PUTU32(pt + 12, s3);
}
