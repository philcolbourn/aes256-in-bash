#!/bin/bash
#*   Byte-oriented AES-256 implementation.
#*   All lookup tables replaced with 'on the fly' calculations. 
#*
#*   In bash version, lookup tables are retained and 2 others added.
#*
#*   Copyright (c) 2007-2009 Ilya O. Levin, http://www.literatecode.com
#*   Other contributors: Hal Finney
#*
#*   Bash version Copyright (c) 2013 Phil Colbourn
#*
#*   Permission to use, copy, modify, and distribute this software for any
#*   purpose with or without fee is hereby granted, provided that the above
#*   copyright notice and this permission notice appear in all copies.
#*
#*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#


# context
declare -ia key enckey deckey
declare -ia buf

declare -ia sbox=(
    0x63 0x7c 0x77 0x7b 0xf2 0x6b 0x6f 0xc5
    0x30 0x01 0x67 0x2b 0xfe 0xd7 0xab 0x76
    0xca 0x82 0xc9 0x7d 0xfa 0x59 0x47 0xf0
    0xad 0xd4 0xa2 0xaf 0x9c 0xa4 0x72 0xc0
    0xb7 0xfd 0x93 0x26 0x36 0x3f 0xf7 0xcc
    0x34 0xa5 0xe5 0xf1 0x71 0xd8 0x31 0x15
    0x04 0xc7 0x23 0xc3 0x18 0x96 0x05 0x9a
    0x07 0x12 0x80 0xe2 0xeb 0x27 0xb2 0x75
    0x09 0x83 0x2c 0x1a 0x1b 0x6e 0x5a 0xa0
    0x52 0x3b 0xd6 0xb3 0x29 0xe3 0x2f 0x84
    0x53 0xd1 0x00 0xed 0x20 0xfc 0xb1 0x5b
    0x6a 0xcb 0xbe 0x39 0x4a 0x4c 0x58 0xcf
    0xd0 0xef 0xaa 0xfb 0x43 0x4d 0x33 0x85
    0x45 0xf9 0x02 0x7f 0x50 0x3c 0x9f 0xa8
    0x51 0xa3 0x40 0x8f 0x92 0x9d 0x38 0xf5
    0xbc 0xb6 0xda 0x21 0x10 0xff 0xf3 0xd2
    0xcd 0x0c 0x13 0xec 0x5f 0x97 0x44 0x17
    0xc4 0xa7 0x7e 0x3d 0x64 0x5d 0x19 0x73
    0x60 0x81 0x4f 0xdc 0x22 0x2a 0x90 0x88
    0x46 0xee 0xb8 0x14 0xde 0x5e 0x0b 0xdb
    0xe0 0x32 0x3a 0x0a 0x49 0x06 0x24 0x5c
    0xc2 0xd3 0xac 0x62 0x91 0x95 0xe4 0x79
    0xe7 0xc8 0x37 0x6d 0x8d 0xd5 0x4e 0xa9
    0x6c 0x56 0xf4 0xea 0x65 0x7a 0xae 0x08
    0xba 0x78 0x25 0x2e 0x1c 0xa6 0xb4 0xc6
    0xe8 0xdd 0x74 0x1f 0x4b 0xbd 0x8b 0x8a
    0x70 0x3e 0xb5 0x66 0x48 0x03 0xf6 0x0e
    0x61 0x35 0x57 0xb9 0x86 0xc1 0x1d 0x9e
    0xe1 0xf8 0x98 0x11 0x69 0xd9 0x8e 0x94
    0x9b 0x1e 0x87 0xe9 0xce 0x55 0x28 0xdf
    0x8c 0xa1 0x89 0x0d 0xbf 0xe6 0x42 0x68
    0x41 0x99 0x2d 0x0f 0xb0 0x54 0xbb 0x16
)
declare -ia sbox_inv=(
    0x52 0x09 0x6a 0xd5 0x30 0x36 0xa5 0x38
    0xbf 0x40 0xa3 0x9e 0x81 0xf3 0xd7 0xfb
    0x7c 0xe3 0x39 0x82 0x9b 0x2f 0xff 0x87
    0x34 0x8e 0x43 0x44 0xc4 0xde 0xe9 0xcb
    0x54 0x7b 0x94 0x32 0xa6 0xc2 0x23 0x3d
    0xee 0x4c 0x95 0x0b 0x42 0xfa 0xc3 0x4e
    0x08 0x2e 0xa1 0x66 0x28 0xd9 0x24 0xb2
    0x76 0x5b 0xa2 0x49 0x6d 0x8b 0xd1 0x25
    0x72 0xf8 0xf6 0x64 0x86 0x68 0x98 0x16
    0xd4 0xa4 0x5c 0xcc 0x5d 0x65 0xb6 0x92
    0x6c 0x70 0x48 0x50 0xfd 0xed 0xb9 0xda
    0x5e 0x15 0x46 0x57 0xa7 0x8d 0x9d 0x84
    0x90 0xd8 0xab 0x00 0x8c 0xbc 0xd3 0x0a
    0xf7 0xe4 0x58 0x05 0xb8 0xb3 0x45 0x06
    0xd0 0x2c 0x1e 0x8f 0xca 0x3f 0x0f 0x02
    0xc1 0xaf 0xbd 0x03 0x01 0x13 0x8a 0x6b
    0x3a 0x91 0x11 0x41 0x4f 0x67 0xdc 0xea
    0x97 0xf2 0xcf 0xce 0xf0 0xb4 0xe6 0x73
    0x96 0xac 0x74 0x22 0xe7 0xad 0x35 0x85
    0xe2 0xf9 0x37 0xe8 0x1c 0x75 0xdf 0x6e
    0x47 0xf1 0x1a 0x71 0x1d 0x29 0xc5 0x89
    0x6f 0xb7 0x62 0x0e 0xaa 0x18 0xbe 0x1b
    0xfc 0x56 0x3e 0x4b 0xc6 0xd2 0x79 0x20
    0x9a 0xdb 0xc0 0xfe 0x78 0xcd 0x5a 0xf4
    0x1f 0xdd 0xa8 0x33 0x88 0x07 0xc7 0x31
    0xb1 0x12 0x10 0x59 0x27 0x80 0xec 0x5f
    0x60 0x51 0x7f 0xa9 0x19 0xb5 0x4a 0x0d
    0x2d 0xe5 0x7a 0x9f 0x93 0xc9 0x9c 0xef
    0xa0 0xe0 0x3b 0x4d 0xae 0x2a 0xf5 0xb0
    0xc8 0xeb 0xbb 0x3c 0x83 0x53 0x99 0x61
    0x17 0x2b 0x04 0x7e 0xba 0x77 0xd6 0x26
    0xe1 0x69 0x14 0x63 0x55 0x21 0x0c 0x7d
)

# eg. DUMP key 32 
DUMP(){
    local _a=$1
    local -i _n=$2 _v _i
    #printf "DUMP $1 $2\n"
    printf "%20s %6s:" ${FUNCNAME[1]} $_a
    for (( _i=0; _i<_n; _i++ )); do 
        eval "_v=\${$_a[_i]}"
        (( _i&3 )) || printf " "
        printf "%02x" $_v
    done;
    printf "\n"
}


# xtime values and F macro generate identical values - using xtime method
declare -ia xtime F FD

for (( x=0; x<0x100; x++ )); do
    (( xtime[x]=(x&0x80) ? (((x<<1)&0xff)^0x1b) : ((x<<1)&0xff) ));
    #(( F[x]=((x<<1)&0xff)^((((x>>7)&1)*0x1b)&0xff) ));
    (( FD[x]=(x>>1)^( (x&1)?0x8d:0 ) ));
done

aes_subBytes(){
    local -i i=16;
    while (( i-- )); do 
        (( buf[i]=sbox[ buf[i] ] ));
    done;
}

aes_subBytes_inv(){
    local -i i=16;
    while (( i-- )); do
        (( buf[i]=sbox_inv[ buf[i] ] ));
    done;
}

# pass offset into key array. usually 0, sometimes 16
aes_addRoundKey(){
    local -i o=$1                                # key[o] starting point offset
    local -i i=16;
    while (( i-- )); do
        (( buf[i]^=key[i+o] ));
    done;
}

# aes_addRoundKey_cpy replaced with these 2 functions for enckey and deckey
aes_addRoundKey_cpy_dec_to_key(){
    local -i i=16;
    while (( i-- ));do
       (( key[i]=deckey[i] ));
       (( key[16+i]=deckey[16+i] ));
       (( buf[i]^=key[i] ));
    done;
}

aes_addRoundKey_cpy_enc_to_key(){
    local -i i=16;
    while (( i-- ));do
       (( key[i]=enckey[i] ));
       (( key[16+i]=enckey[16+i] ));
       (( buf[i]^=key[i] ));
    done;
}

aes_shiftRows(){
    local -i i j;
    (( i=buf[1],   buf[1]=buf[5],   buf[5]=buf[9],   buf[9]=buf[13], buf[13]=i ));
    (( i=buf[10], buf[10]=buf[2],   buf[2]=i ));
    (( j=buf[3],   buf[3]=buf[15], buf[15]=buf[11], buf[11]=buf[7],   buf[7]=j ));
    (( j=buf[14], buf[14]=buf[6],   buf[6]=j ));
}

aes_shiftRows_inv(){
    local -i i j;
    (( i=buf[1], buf[1]=buf[13], buf[13]=buf[9],   buf[9]=buf[5],   buf[5]=i ));
    (( i=buf[2], buf[2]=buf[10], buf[10]=i ));
    (( j=buf[3], buf[3]=buf[7],   buf[7]=buf[11], buf[11]=buf[15], buf[15]=j ));
    (( j=buf[6], buf[6]=buf[14], buf[14]=j ));
}

aes_mixColumns(){
    local -i i a b c d e;
    for (( i=0; i<16; i+=4 )); do
        (( a=buf[i]   ));
        (( b=buf[i+1] )); 
        (( c=buf[i+2] )); 
        (( d=buf[i+3] ));
        (( e=a^b^c^d  ));
        ((   buf[i]^=e^xtime[a^b] ));
        (( buf[i+1]^=e^xtime[b^c] ));
        (( buf[i+2]^=e^xtime[c^d] )); 
        (( buf[i+3]^=e^xtime[d^a] ));
    done
}

aes_mixColumns_inv(){
    local -i i a b c d e x y z;
    for (( i=0; i<16; i+=4 )); do
        (( a=buf[i]   ));
        (( b=buf[i+1] )); 
        (( c=buf[i+2] )); 
        (( d=buf[i+3] ));
        (( e=a^b^c^d  ));
        (( z=xtime[e] ));
        (( x=e^xtime[ xtime[z^a^c] ] ));  
        (( y=e^xtime[ xtime[z^b^d] ] ));
        ((   buf[i]^=x^xtime[a^b] ));
        (( buf[i+1]^=y^xtime[b^c] ));
        (( buf[i+2]^=x^xtime[c^d] )); 
        (( buf[i+3]^=y^xtime[d^a] ));
    done
}

aes_expandEncKey() {
    local -i i;                                  # rc from caller
    (( key[0]^=sbox[ key[29] ]^rc ));
    (( key[1]^=sbox[ key[30] ]    ));
    (( key[2]^=sbox[ key[31] ]    ));
    (( key[3]^=sbox[ key[28] ]    ));

    #(( rc=F[rc] ));
    (( rc=xtime[rc] ));
    
    for (( i=4; i<16; i+=4 )); do
        (( key[i]^=key[i-4],   
         key[i+1]^=key[i-3], 
         key[i+2]^=key[i-2], 
         key[i+3]^=key[i-1] ));
    done;
    (( key[16]^=sbox[ key[12] ] ));
    (( key[17]^=sbox[ key[13] ] ));
    (( key[18]^=sbox[ key[14] ] ));
    (( key[19]^=sbox[ key[15] ] ));

    for (( i=20; i<32; i+=4 )); do 
        ((   key[i]^=key[i-4],
           key[i+1]^=key[i-3], 
           key[i+2]^=key[i-2], 
           key[i+3]^=key[i-1] ));
    done;
}

# aes256_init call aes_expandEncKey with deckey so this is needed for this special case
aes_expandEncKey_using_dec_key() {
    local -i i;                                  # rc from caller
    (( deckey[0]^=sbox[ deckey[29] ]^rc ));
    (( deckey[1]^=sbox[ deckey[30] ]    ));
    (( deckey[2]^=sbox[ deckey[31] ]    ));
    (( deckey[3]^=sbox[ deckey[28] ]    ));

    #(( rc=F[rc] ));
    (( rc=xtime[rc] ));
    
    for (( i=4; i<16; i+=4 )); do
        (( deckey[i]^=deckey[i-4],   
         deckey[i+1]^=deckey[i-3], 
         deckey[i+2]^=deckey[i-2], 
         deckey[i+3]^=deckey[i-1] ));
    done;
    (( deckey[16]^=sbox[ deckey[12] ] ));
    (( deckey[17]^=sbox[ deckey[13] ] ));
    (( deckey[18]^=sbox[ deckey[14] ] ));
    (( deckey[19]^=sbox[ deckey[15] ] ));

    for (( i=20; i<32; i+=4 )); do 
        ((   deckey[i]^=deckey[i-4],
           deckey[i+1]^=deckey[i-3], 
           deckey[i+2]^=deckey[i-2], 
           deckey[i+3]^=deckey[i-1] ));
    done;
}

aes_expandDecKey(){
    local -i i;                                  # rc from caller
    for (( i=28; i>16; i-=4 )); do
        (( key[i+0]^=key[i-4], 
           key[i+1]^=key[i-3], 
           key[i+2]^=key[i-2], 
           key[i+3]^=key[i-1] ));
    done
    
    (( key[16]^=sbox[ key[12] ] ));
    (( key[17]^=sbox[ key[13] ] ));
    (( key[18]^=sbox[ key[14] ] ));
    (( key[19]^=sbox[ key[15] ] ));

    for (( i=12; i>0; i-=4 )); do
        (( key[i+0]^=key[i-4], 
           key[i+1]^=key[i-3], 
           key[i+2]^=key[i-2], 
           key[i+3]^=key[i-1] ));
    done
    
    (( rc=FD[rc] ));

    (( key[0]^=sbox[ key[29] ]^rc ));
    (( key[1]^=sbox[ key[30] ]    ));
    (( key[2]^=sbox[ key[31] ]    ));
    (( key[3]^=sbox[ key[28] ]    ));
#eval $DUMP_ALL;
}

# pass initial key
aes256_init(){
    local -ia k=($*)
    local -i rc=1;                               # rcon needs to be called rc
    local -i i;
    for (( i=0; i<32; i++ )); do 
        (( enckey[i]=deckey[i]=key[i]=k[i] ));   # this is a little different from original
    done;
    for (( i=8; --i; )); do 
        aes_expandEncKey_using_dec_key;          # use special version of aes_expandEncKey
    done;
}

aes256_done(){
    local -i i;
    for (( i=0; i<32; i++ )); do 
        (( key[i]=enckey[i]=deckey[i]=0 ));
    done
}

aes256_encrypt_ecb(){
    local -i i rc;                               # rcon must called rc;
    aes_addRoundKey_cpy_enc_to_key;
    for (( i=1, rc=1; i<14; ++i )); do
        aes_subBytes;
        aes_shiftRows;
        aes_mixColumns;
        if (( i&1 )); then
            aes_addRoundKey 16;                  # from key[16]
        else 
            aes_expandEncKey;
            aes_addRoundKey 0;
        fi
    done
    aes_subBytes;
    aes_shiftRows;
    aes_expandEncKey; 
    aes_addRoundKey 0;
}

aes256_decrypt_ecb(){
    local -i i rc;
    aes_addRoundKey_cpy_dec_to_key;
    aes_shiftRows_inv;
    aes_subBytes_inv;

    for (( i=14, rc=0x80; --i; )); do
        if (( i&1 )); then
            aes_expandDecKey;
            aes_addRoundKey 16;                  # from key[16]
        else
            aes_addRoundKey 0;
        fi
        aes_mixColumns_inv;
        aes_shiftRows_inv;
        aes_subBytes_inv;
    done
    aes_addRoundKey 0; 
}


declare -ia buf=({0..15})                        # setup text as 0..15
#for (( x=0; x<16; x++ )); do                     # setup text as 00 11 ... ff
#    (( buf[x]=x*16+x ));
#done

printf "Start with this cleartext\n"
DUMP buf 16
aes256_init {0..31}                              # 32 byte key here
aes256_encrypt_ecb

printf "Encrypted text\n"
DUMP buf 16

#buf=(0x8e 0xd0 0x92 0x3f 0x5b 0x2c 0x65 0x0f 0x31 0xa5 0xdd 0x42 0x24 0x63 0x37 0x7f)

aes256_init {0..31}
aes256_decrypt_ecb
printf "Recover cleartext\n"
DUMP buf 16

