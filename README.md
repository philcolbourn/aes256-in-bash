# aes256-in-bash
Automatically exported from code.google.com/p/aes256-in-bash

Implementation of AES256 16B in Bash.

Based on "A byte-oriented AES-256 implementation" by Ilya Levin http://www.literatecode.com/aes256

Basically a simple translation, taking some old bash bugs into account.

Passes all KAT 256.rsp tests except CFB tests from http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip

Table based using sbox and sbox_inv tables rather than functions. Macros F and FD as well as function xtime are implemented as computed tables.

F is actually no longer generated since it is identical (in operation) to xtime.

#define F(x)   (((x) << 1) ^ ((((x)>>7) & 1) * 0x1b))
#define FD(x)  (((x) >> 1) ^ (((x) & 1) ? 0x8d : 0))
uint8_t rj_xtime(uint8_t x) 
{
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
} /* rj_xtime */
