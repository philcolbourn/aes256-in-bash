Implementation of AES256 16B in Bash.

Based on "A byte-oriented AES-256 implementation" by Ilya Levin http://www.literatecode.com/aes256

Basically a simple translation, taking some old bash bugs into account.

Passes all KAT **256.rsp tests except CFB** tests from http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip

Table based using _sbox_ and _sbox\_inv_ tables rather than functions.
Macros _F_ and _FD_ as well as function _xtime_ are implemented as computed tables.

_F_ is actually no longer generated since it is identical (in operation) to _xtime_.

```
#define F(x)   (((x) << 1) ^ ((((x)>>7) & 1) * 0x1b))
#define FD(x)  (((x) >> 1) ^ (((x) & 1) ? 0x8d : 0))
uint8_t rj_xtime(uint8_t x) 
{
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
} /* rj_xtime */
```