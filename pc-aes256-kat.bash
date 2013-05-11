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

# context
declare -ia key enckey deckey
declare -ia buf

# pre-computed tables
# xtime values and F macro generate identical values - using xtime method
# also replace sbox and sbox_inv. To do this make multiv, log, and alog tables
declare -ia sbox sbox_inv
declare -ia gf_alog gf_log gf_mulinv
declare -ia xtime F FD

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

make_gf_alog(){  # // calculate anti-logarithm gen 3
    local -i x=$1 atb=1 z i;
    i=x;
    while (( i-- )); do
        (( z=atb, atb=(atb<<1)&0xff, atb^=(z&0x80)?0x1b:0, atb^=z ));
    done
    gf_alog[x]=atb;
}

make_gf_log(){  # // calculate logarithm gen 3
    local -i x=$1 atb=1 i z;
    for (( i=0; i<0x100; i++ )); do
        (( atb==x )) && break;
        (( z=atb, atb=(atb<<1)&0xff, atb^=(z&0x80)?0x1b:0, atb^=z ));
    done
    (( gf_log[x]=i&0xff ));
}

make_rj_sbox(){
    local -i x=$1 y sb;
    (( sb=y=gf_mulinv[x] ));
    (( y=((y<<1)&0xff)|(y>>7), sb^=y, y=((y<<1)&0xff)|(y>>7), sb^=y )); 
    (( y=((y<<1)&0xff)|(y>>7), sb^=y, y=((y<<1)&0xff)|(y>>7), sb^=y ));
    (( sbox[x]=sb^0x63 ));
}

make_rj_sbox_inv(){
    local -i x=$1 y sb;
    (( y=x^0x63 ));
    (( sb=y=((y<<1)&0xff)|(y>>7) ));
    (( y=((y<<2)&0xff)|(y>>6), sb^=y, y=((y<<3)&0xff)|(y>>5), sb^=y ));
    (( sbox_inv[x]=gf_mulinv[sb] ));
}


for (( x=0; x<0x100; x++ )); do
    (( xtime[x]=(x&0x80) ? (((x<<1)&0xff)^0x1b) : ((x<<1)&0xff) ));
    #(( F[x]=((x<<1)&0xff)^((((x>>7)&1)*0x1b)&0xff) ));
    (( FD[x]=(x>>1)^( (x&1)?0x8d:0 ) ));
    make_gf_alog $x;
    make_gf_log $x;
done

for (( x=0; x<0x100; x++ )); do
    (( gf_mulinv[x]=(x) ? gf_alog[ 255-gf_log[x] ] : 0 ));  # // calculate multiplicative inverse
done

for (( x=0; x<0x100; x++ )); do
    make_rj_sbox $x;
    make_rj_sbox_inv $x;
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

##########
# Testing 
##########

#KEY = 0000000000000000000000000000000000000000000000000000000000000000
#IV = 00000000000000000000000000000000
#PLAINTEXT = 014730f80ac625fe84f026c60bfd547d
#CIPHERTEXT = 5c9d844ed46f9885085e5d6a4f94c7d7

xor_with_buf(){
    local -ia _iv=($1)
    local -i _i
    for (( _i=0; _i<16; _i++ )); do
        (( buf[_i]^=_iv[_i] ));
    done
}

buf_match_hexstring(){
    local _t="${1}00000000000000000000000000000000" _k
    _t=${_t:0:32}  # limit to 32 hex digits
    local -i _i _v
    for (( _i=0; _i<16; _i++ )); do
        eval _v=0x${_t:_i*2:2}
        (( buf[_i]!=_v )) && return 1
    done
    return 0
}

xor_buf_with_hexstring(){
    local _t="${1}00000000000000000000000000000000" _k
    _t=${_t:0:32}  # limit to 32 hex digits
    local -i _i _v
    for (( _i=0; _i<16; _i++ )); do
        eval _v=0x${_t:_i*2:2}
        (( buf[_i]^=_v ))
    done
}

set_buf_from_hexstring(){
#set -x
    local _t="${1}00000000000000000000000000000000" _k
    _t=${_t:0:32}  # limit to 32 hex digits
    local -i _i _v
    for (( _i=0; _i<16; _i++ )); do
        eval buf[_i]=0x${_t:_i*2:2}
    done
#set +x
}

set_key_from_hexstring(){
    local _t="${1}0000000000000000000000000000000000000000000000000000000000000000" _k
    _t=${_t:0:64}  # limit to 32 hex digits
    local -i _i
    for (( _i=0; _i<32; _i++ )); do
        _k+="0x"${_t:_i*2:2}" "
    done
    RET=$_k
}

#buf=(0x8e 0xd0 0x92 0x3f 0x5b 0x2c 0x65 0x0f 0x31 0xa5 0xdd 0x42 0x24 0x63 0x37 0x7f)

##########
# test a KAT set
##########

# assume KEY, IV, CIPHERTEXT, and PLAINTEXT are set from caller
process_set(){
    local _mode=$1 _m=$2
    # run test
    printf "KEY=$KEY\n"
    printf "IV=$IV\n"
    printf "CIPHERTEXT=$CIPHERTEXT\n"
    printf "PLAINTEXT=$PLAINTEXT\n"
    set_key_from_hexstring $KEY
    aes256_init $RET                              # 32 byte key here

    if [[ $_m == "enc" ]]; then

        case $_mode in
                 ECB) set_buf_from_hexstring $PLAINTEXT
                      aes256_encrypt_ecb
                      ;;
            CBC|PCBC) set_buf_from_hexstring $PLAINTEXT
                      xor_buf_with_hexstring $IV
                      aes256_encrypt_ecb
                      ;;
             CFB|OFB) set_buf_from_hexstring $IV
                      aes256_encrypt_ecb
                      xor_buf_with_hexstring $PLAINTEXT
                      ;;
                   *) printf "ERROR: Unknown mode [$_mode]\n"; exit 1
        esac

        if buf_match_hexstring $CIPHERTEXT; then
            printf "PASS\n"
        else
            printf "FAIL\n"
            DUMP buf 16
            printf "Expected: $CIPHERTEXT\n"
            return 1
        fi
    else
        set_buf_from_hexstring $CIPHERTEXT

        case $_mode in
                 ECB) set_buf_from_hexstring $CIPHERTEXT
                      aes256_decrypt_ecb
                      ;;
            CBC|PCBC) set_buf_from_hexstring $CIPHERTEXT
                      xor_buf_with_hexstring $IV
                      aes256_decrypt_ecb
                      ;;
             CFB|OFB) set_buf_from_hexstring $IV
                      aes256_encrypt_ecb
                      xor_buf_with_hexstring $CIPHERTEXT
                      ;;
                   *) printf "ERROR: Unknown mode [$_mode]\n"; exit 1
        esac

        if buf_match_hexstring $PLAINTEXT; then
            printf "PASS\n"
        else
            printf "FAIL\n"
            DUMP buf 16
            printf "Expected: $PLAINTEXT\n"
            return 1
        fi
    fi
    return 0
}

##########
# Tet KAT sets from a file
##########

process_file(){
    local _mode=$1
    local _k _e _v _r _m=enc
    printf -v IFS " \t\n\r"
    # skip to first COUNT = 
    while read _k _e v; do
        _k=${_k//[[:cntrl:]]/}
        #printf "{$_k}\n"
        [[ $_k == "[ENCRYPT]" ]] && { printf "ENCRYPT MODE\n"; _m=enc; }
        [[ $_k == "COUNT" ]] && break
    done
    # read test
    while [[ $_k == "COUNT" ]]; do
        while { read _k _e _v _r; [[ $_e != "" ]]; }; do
            _k=${_k//[[:cntrl:]]/}; eval $_k=$_v
        done

        process_set $_mode $_m
        [[ $? -ne 0 ]] && exit 1
        
        # sync to next test
        while read _k _e v; do
            _k=${_k//[[:cntrl:]]/}
            #printf "{$_k}\n"
            [[ $_k == "[DECRYPT]" ]] && { printf "DECRYPT MODE\n"; _m=dec; }
            [[ $_k == "COUNT" ]] && break
        done
        #sleep 1
    done
}

run_KAT_AES_tests(){
    local _f
    #for _f in KAT_AES/ECBGFSbox256.rsp; do
    for _f in KAT_AES/*256.rsp; do
        mode=$_f
        mode=${mode#*\/}
        mode=${mode%Key*}
        mode=${mode%Var*}
        mode=${mode%GF*}
        mode=${mode%128*}
        mode=${mode%1*}
        mode=${mode%8*}
        printf "PROCESS $_f: MODE=$mode\n"
        process_file $mode < "$_f"
    done
}

# FIXME: CFB tests fail
# FIXME: some tests generate 'command not found' errors in line 490-ish - probably extra character in input
run_KAT_AES_tests

exit 0

##########
# looking at ASCII encoding of hex strings - incomplete
##########

declare -i ORD
ord(){ printf -v ORD '%d' "'$1"; }

#chr(){ printf \\$(printf '%03o' $1); }

make_hexstring_from_ASCII(){
    local -i _i
    local _t="$1" _o _v
    for (( _i=0; _i<16; _i++ )); do
        ord ${_t:_i:1}
        printf -v _v "%02x" $ORD
        _o="${_o}$_v"
    done
    RET="$_o"
}

make_base95_from_buf(){
    local -i _i _v _carry
    local _c _o
    for (( _i=0; _i<16; _i++ )); do
        (( _v=(_carry*95 + buf[_i])%95+33 ));
        (( _carry=buf[_i]%95 ));
        printf -v _c "\\\x%02x" $_v
        _o="${_o}${_c}"
    done
    RET="$_o"
}

try(){
    local _mode
    for _mode in ECB CBC PCBC OFB; do
        KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        IV=0102030405060708090a0b0c0d0e0f
        CIPHERTEXT=0
        make_hexstring_from_ASCII "password"
        PLAINTEXT=$RET
        process_set ECB enc
        make_base95_from_buf
        printf "CT=[[ %b ]]\n" $RET
    done
}

try

exit 0

##########
# initial testing 
##########

printf "Init keys\n"
#aes256_init {0..31}                              # 32 byte key here
set_key_from_hexstring 0
aes256_init $RET                              # 32 byte key here
DUMP enckey 32
DUMP deckey 32


printf "Start with this cleartext\n"
set_buf_from_hexstring 014730f80ac625fe84f026c60bfd547d
#buf=({0..15})                                    # setup text as 0..15
#for (( x=0; x<16; x++ )); do                     # setup text as 00 11 ... ff
#    (( buf[x]=x*16+x ));
#done
DUMP buf 16
aes256_encrypt_ecb

printf "Encrypted text\n"
DUMP buf 16

printf "Recover cleartext\n"
aes256_decrypt_ecb
DUMP buf 16

