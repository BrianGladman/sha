/*
---------------------------------------------------------------------------
Copyright (c) 1998-2010, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007
*/

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>

/* define to send output to console         */
#define TO_CONSOLE
#define SHA_64BIT

/* order of these includes matters since	*/
/* sha2 may set the need for 64-bit types	*/
/* that sha1 doesn't need					*/

#include "sha1.h"
#include "sha2.h"

/* prefixes for input/output to/from files  */
const char *in_file_prefix  = "..\\testvals\\messages.";
const char *out_file_prefix = "..\\outvals\\hash.";

/* define which algorithms to test          */
#define   TEST_SHA1
#define TEST_SHA224
#define TEST_SHA256
#ifdef SHA_64BIT
#define TEST_SHA384
#define TEST_SHA512
#else
#undef  TEST_SHA384
#undef  TEST_SHA512
#endif

/* Standard 'Basic String' test vectors     */

struct
{   char*  str[6];
} byte_v1[6] =
{
 {  "abc",
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
 },
 {  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
    "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
 },
 {  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "a49b2446a02c645bf419f995b67091253a04a259",
    "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
 },
 {  "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
    "d8cc4fd0a57d0e0e96cdb3e74164f734c593ed65",
    "3c716dbd86c4c6e182aa34f9d156f23d79cc18024706cbe8b5652b86",
    "941ac378682e3dc66275dd49d5fb09978754ecf4231d18d30326fa51962648ec",
    "3d208973ab3508dbbd7e2c2862ba290ad3010e4978c198dc4d8fd014e582823a89e16f9b2a7bbc1ac938e2d199e8bea4",
    "930d0cefcb30ff1133b6898121f1cf3d27578afcafe8677c5257cf069911f75d8f5831b56ebfda67b278e66dff8b84fe2b2870f742a580d8edb41987232850c9"
 },
 {  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",   /*...1000000...*/
    "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
    "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
 },
 {  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",   /*...100000000...*/
    "812ed6a931408fca6b4881a1cd3308ae306cde96",
    "34383e1e14a1bb22c8c8433de612b52a343d5ca8cfe94c98fac6374c",
    "83d30385a4a11980275dc23de3fb49ff37b906cc841efa048a96c62d90ff3b5f",
    "0680b808825c2c253c94258e37a30f41e45f2f635ad130bf699a83812bc3071cd03e84c02254ea1a6886a211e3a774f8",
    "eb450744183ed1bdbf7472b15d88becc4b3e82b23f3f7d4dbe585f51e139789e8ff2fc70aaa4ea1b07132dc9504e68746366f67c9210929516bc0b0c55144b8a"
 }
};

/*
 *  FIPS PUB 180-4 test vectors for SHA-512/t obtained from:
 *    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA512_224.pdf
 *    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA512_256.pdf
 */
struct
{   char          *str;
    unsigned char sha512_224[224 >> 3];
    unsigned char sha512_256[256 >> 3];
} byte_v2[2] =
{
 {  "abc",
    {0x46, 0x34, 0x27, 0x0F, 0x70, 0x7B, 0x6A, 0x54, 0xDA, 0xAE, 0x75, 0x30, 0x46, 0x08,
     0x42, 0xE2, 0x0E, 0x37, 0xED, 0x26, 0x5C, 0xEE, 0xE9, 0xA4, 0x3E, 0x89, 0x24, 0xAA},
    {0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E, 0x29, 0xB7, 0x6B, 0x4C, 0x7D, 0xAB,
     0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC, 0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31, 0x07, 0xE7, 0xAF, 0x23}
 },
 {  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    {0x23, 0xFE, 0xC5, 0xBB, 0x94, 0xD6, 0x0B, 0x23, 0x30, 0x81, 0x92, 0x64, 0x0B, 0x0C,
     0x45, 0x33, 0x35, 0xD6, 0x64, 0x73, 0x4F, 0xE4, 0x0E, 0x72, 0x68, 0x67, 0x4A, 0xF9},
    {0x39, 0x28, 0xE1, 0x84, 0xFB, 0x86, 0x90, 0xF8, 0x40, 0xDA, 0x39, 0x88, 0x12, 0x1D, 0x31, 0xBE,
     0x65, 0xCB, 0x9D, 0x3E, 0xF8, 0x3E, 0xE6, 0x14, 0x6F, 0xEA, 0xC8, 0x61, 0xE1, 0x9B, 0x56, 0x3A}
 }
};

/* SHA1 test vectors from Jim Gillogly  */
/* and Francois Grieu. In this version  */
/* they are defined as a repeating byte */
/* sequence and a final bit sequence    */

typedef struct
{   unsigned char rep_bytes[3];
    int           rep_cnt;
    char          *end_bits;
    char          *hash;
} bit1_str;

bit1_str bit1_gge[12] =
{   { { 0xdb, 0x6d, 0xb6 }, 18,    "11011011011011", "ce7387ae577337be54ea94f82c842e8be76bc3e1" },
    { { 0xdb, 0x6d, 0xb6 }, 18,   "110110110110110", "de244f063142cb2f4c903b7f7660577f9e0d8791" },
    { { 0xdb, 0x6d, 0xb6 }, 18,  "1101101101101101", "a3d2982427ae39c8920ca5f499d6c2bd71ebf03c" },
    { { 0xdb, 0x6d, 0xb6 }, 18, "11011011011011011", "351aab58ff93cf12af7d5a584cfc8f7d81023d10" },
    { { 0xdb, 0x6d, 0xb6 }, 21,            "110110", "996386921e480d4e2955e7275df3522ce8f5ab6e" },
    { { 0xdb, 0x6d, 0xb6 }, 21,           "1101101", "bb5f4ad48913f51b157eb985a5c2034b8243b01b" },
    { { 0xdb, 0x6d, 0xb6 }, 21,          "11011011", "9e92c5542237b957ba2244e8141fdb66dec730a5" },
    { { 0xdb, 0x6d, 0xb6 }, 21,         "110110110", "2103e454da4491f4e32dd425a3341dc9c2a90848" },
    { { 0x6d, 0xb6, 0xdb }, 61,            "011011", "b4b18049de405027528cd9e74b2ec540d4e6f06b" },
    { { 0x6d, 0xb6, 0xdb }, 61,           "0110110", "34c63356b308742720ab966914eb0fc926e4294b" },
    { { 0x6d, 0xb6, 0xdb }, 61,          "01101101", "75face1802b9f84f326368ab06e73e0502e9ea34" },
    { { 0x6d, 0xb6, 0xdb }, 61,         "011011011", "7c2c3d62f6aec28d94cdf93f02e739e7490698a1" },
};

bit1_str bit1_ggh[8] =
{   { { 0xdb, 0x6d, 0xb6 }, 178956970,    "11011011011011", "1eef5a18969255a3b1793a2a955c7ec28cd221a5" },
    { { 0xdb, 0x6d, 0xb6 }, 178956970,   "110110110110110", "7a1045b914672aface8d90e6d19b3a6ada3cb879" },
    { { 0xdb, 0x6d, 0xb6 }, 178956970,  "1101101101101101", "d5e09777a94f1ea9240874c48d9fecb6b634256b" },
    { { 0xdb, 0x6d, 0xb6 }, 178956970, "11011011011011011", "eb2569043c3014e51b2862ae6eb5fb4e0b851d99" },
    { { 0x6d, 0xb6, 0xdb }, 178956970,    "01101101101101", "4cb0c4ef69143d5bf34fc35f1d4b19f6eccae0f2" },
    { { 0x6d, 0xb6, 0xdb }, 178956970,   "011011011011011", "47d92f911fc7bb74de00adfc4e981a8105556d52" },
    { { 0x6d, 0xb6, 0xdb }, 178956970,  "0110110110110110", "a3d7438c589b0b932aa91cc2446f06df9abc73f0" },
    { { 0x6d, 0xb6, 0xdb }, 178956970, "01101101101101101", "3eee3e1e28dede2ca444d68da5675b2faaab3203" }
};

/* SHA1 test vectors from Jim Gillogly  */
/* and Francois Grieu. In this version  */
/* they are defined as a repeating bit  */
/* sequence and a final bit sequence    */

typedef struct
{   unsigned char rep_byte;
    int           rep_cnt;
    char          *end_bits;
    char          *hash;
} bit2_str;

bit2_str bit2_gge[12] =
{   /*  vv  -- most significant three bits of bytes */
    { 0xc0,        148,    "11", "ce7387ae577337be54ea94f82c842e8be76bc3e1" },
    { 0xc0,        149,      "", "de244f063142cb2f4c903b7f7660577f9e0d8791" },
    { 0xc0,        149,     "1", "a3d2982427ae39c8920ca5f499d6c2bd71ebf03c" },
    { 0xc0,        149,    "11", "351aab58ff93cf12af7d5a584cfc8f7d81023d10" },
    { 0xc0,        170,      "", "996386921e480d4e2955e7275df3522ce8f5ab6e" },
    { 0xc0,        170,     "1", "bb5f4ad48913f51b157eb985a5c2034b8243b01b" },
    { 0xc0,        170,    "11", "9e92c5542237b957ba2244e8141fdb66dec730a5" },
    { 0xc0,        171,      "", "2103e454da4491f4e32dd425a3341dc9c2a90848" },
    { 0x60,        490,      "", "b4b18049de405027528cd9e74b2ec540d4e6f06b" },
    { 0x60,        490,     "0", "34c63356b308742720ab966914eb0fc926e4294b" },
    { 0x60,        490,    "01", "75face1802b9f84f326368ab06e73e0502e9ea34" },
    { 0x60,        491,      "", "7c2c3d62f6aec28d94cdf93f02e739e7490698a1" },
};

bit2_str bit2_ggh[8] =
{   /*  vv  -- most significant three bits of bytes */
    { 0xc0, 1431655764,    "11", "1eef5a18969255a3b1793a2a955c7ec28cd221a5" },
    { 0xc0, 1431655764,   "110", "7a1045b914672aface8d90e6d19b3a6ada3cb879" },
    { 0xc0, 1431655764,  "1101", "d5e09777a94f1ea9240874c48d9fecb6b634256b" },
    { 0xc0, 1431655764, "11011", "eb2569043c3014e51b2862ae6eb5fb4e0b851d99" },
    { 0x60, 1431655764,    "01", "4cb0c4ef69143d5bf34fc35f1d4b19f6eccae0f2" },
    { 0x60, 1431655764,   "011", "47d92f911fc7bb74de00adfc4e981a8105556d52" },
    { 0x60, 1431655764,  "0110", "a3d7438c589b0b932aa91cc2446f06df9abc73f0" },
    { 0x60, 1431655764, "01101", "3eee3e1e28dede2ca444d68da5675b2faaab3203" }
};

typedef void (*f_begin)(void* cx);
typedef void (*f_hash)(const unsigned char d[], unsigned long l, void* cx);
typedef void (*f_end)(unsigned char h[], void* cx);

enum hash        {    SHA2 = 0,   SHA1 = 1, SHA224 = 2, SHA256 =  3,
                    SHA384 = 4, SHA512 = 5,   BITS = 8,  BYTES = 16 };

char *h_name[] = { "sha2", "sha1", "sha224", "sha256", "sha384", "sha512",
                   "bits", "bytes" };

enum test     { basic_byte =  1,
                cs_bytes   =  2, cs_bits    =  4,
                gg_easy_by =  8, gg_hard_by = 16,
                gg_easy_bi = 32, gg_hard_bi = 64 };

char *t_name[] =
{
    "\nTest Data: Basic Strings (byte)",
    "\nTest Data: Compact String (type %01d, byte)",
    "\nTest Data: Compact String (type %01d, bit)",
    "\nTest Data: Gillogly/Grieu E (bit -> %s)",
    "\nTest Data: Gillogly/Grieu H (bit -> %s)",
};

typedef union
{   sha1_ctx  cx1;
    sha2_ctx  cx2;
} u_ctx;

typedef struct
{   enum hash       h_n;
    unsigned long   h_len;
    u_ctx           cx[1];
    f_begin         f_b;
    f_hash          f_h;
    f_end           f_e;
} hash_ctx;

char* hexd = "0123456789ABCDEF";

void hash_out(char h[], unsigned int len, int err, FILE *fo)
{	int i;

    if(!fo) return;
        
    fprintf(fo, "\n");

    for(i = 0; i < (int)len; ++i)
        fprintf(fo, "%c%c", hexd[(h[i] >> 4) & 15], hexd[h[i] & 15]);

    fprintf(fo, (err ? " x" : " ^"));
}

/*  The following code is designed to handle NIST compact strings
    as used in their SHA validation data. These are lists of
    integers separated by spaces in the form

        no initial_bit_value n[0] n[1] ... n[no - 1] ^

    The bit string starts with a first bit whose value (0 or 1)
    is given by initial_bit_value, this is followed by more bits
    of the same value for an overall sequence length of n[0] bits.
    This is followed by n[1] bits of the opposite value and so on,
    there being no sequences overall.  Such compact strings can
    span multiple lines and are ended with a '^' character

    The resulting hash values are in another file in which each
    line contains the hexadecimal value for the hash followed by
    a space and then '^'.

    Comment lines in the file start with # and header dections
    withinn files are of the foem

    H>Header<H

    and data sections

    D>data<D
*/

#define IS_EOF  -1
#define NOT_NUM -2
#define NOT_HEX -3

int get_token(char token[], int n, FILE *f)
{   char chr = '\0';
    int     i = 0;

    while(!feof(f) && (isspace(chr = fgetc(f)) || iscntrl(chr)))
        ;

    if(feof(f)) return IS_EOF;

    while(isalnum(chr) && i < n)
    {
        token[i++] = chr;
        if(feof(f)) break;
        chr = fgetc(f);
    }

    if(!isspace(chr) && !iscntrl(chr))
    {
        if(i == 0 && chr == '<')
        {
            if(i < n) token[i++] = chr;
            if(!feof(f) && i < n) token[i++] = fgetc(f);
        }
        else if(i == 1 && chr == '>')
        {
            if(i < n) token[i++] = chr;
        }
        else if(i == 0 && chr == '#')
        {
            do
            {
                chr = fgetc(f);
            }
            while
                (chr != '\n' && chr != 'r');
        }
        else if(i == 0 && i < n)
            token[i++] = chr;
        else
            ungetc(chr, f);
    }
    if(i < n) token[i] = '\0';
    return i;
}

int token_is(char str[], int len, char slit[])
{
    return (len == strlen(slit) && !strncmp(str, slit, len));
}

int token_to_dec(char str[], int len)
{   int i, no;

    for(i = 0, no = 0; i < len; ++i)
    {
        if(!isdigit(str[i]))
            return NOT_NUM;
        no = 10 * no + (str[i] - '0');
    }
    return no;
}

int token_to_hex(char str[], int len, char *hex_digits)
{   char   chr = 0;
    int             i;

    if(len & 1) return -1;

    for(i = 0; i < len; ++i)
    {
        if(!isxdigit(str[i]))
            return NOT_HEX;
        chr = (chr << 4) | ((str[i] & 0x0f) + (isdigit(str[i]) ? 0 : 9));
        if(i & 1)
            hex_digits[i >> 1] = chr;
    }

    return len >> 1;
}

int out_text(FILE *f, FILE *fo)
{   char    tok[64];
    int     k, n = 0;

    do
    {
        k = get_token(tok, 32, f);
    }
    while
        (k >= 0 && !token_is(tok, k, "H>"));

    if(k > 0 && fo) fprintf(fo, "\nH>");

    k = get_token(tok, 32, f);

    while(k >= 0 && !token_is(tok, k, "<H"))
    {
        if(k == 1 && tok[0] >= '0' && tok[0] <= '9')
            n = tok[0] & 0x0f;
        if(!token_is(tok, k, "Strings"))
        {
            if(k > 0 && fo) fprintf(fo, "%s ", tok);
        }
        else if(fo)
            fprintf(fo, "Hashes");

        k = get_token(tok, 32, f);
    }

    if(k > 0 && fo) fprintf(fo, "<H");

    return k < 0 ? k : n;
}

int get_bitstr(char str[], FILE* f)
{   char    chr[16];
    int     i, l, no, bit, slen, len, pos;

    l = get_token(chr, 16, f);
    if(l < 1 || l == 2 && token_is(chr, l, "<D"))
        return (l < 1 ? l : 0);
    if((no = token_to_dec(chr, l)) < 0)
        return no;

    l = get_token(chr, 16, f);
    if(l < 1 || (bit = token_to_dec(chr, l)) < 0)
        return (l < 1 ? l : bit);

    for(i = 0, len = 0, pos = 0; i < no; ++i)
    {
        l = get_token(chr, 16, f);
        if(l < 1 || (slen = token_to_dec(chr, l)) < 0)
            return (l < 1 ? l : slen);

        if((len & 7) == 0) str[pos] = '\0';
        if(bit)
            while(slen--)
            {
                str[pos] |= 0x80 >> (len & 7);
                if(!(++len & 7)) str[++pos] = '\0';
            }
        else
            while(slen--)
                if(!(++len & 7)) str[++pos] = '\0';
        bit = 1 - bit;
    }

    l = get_token(chr, 16, f);
    if(l != 1 || !token_is(chr, l, "^"))
        return (l < 1 ? l : 0);
    return len;
}

int get_bitstr_hash(char h[], FILE *f, hash_ctx hc[1])
{   char        chr[16], str[128];
    int         i, l, no, bit, slen, len, pos;

    hc->f_b(hc->cx);
    l = get_token(chr, 16, f);
    if(l < 1 || l == 2 && token_is(chr, l, "<D"))
        return (l < 1 ? l : 0);
    if((no = token_to_dec(chr, l)) < 0)
        return no;

    l = get_token(chr, 16, f);
    if(l < 1 || (bit = token_to_dec(chr, l)) < 0)
        return (l < 1 ? l : bit);

    for(i = 0, len = 0, pos = 0; i < no; ++i)
    {
        l = get_token(chr, 16, f);
        if(l < 1 || (slen = token_to_dec(chr, l)) < 0)
            return (l < 1 ? l : slen);

        while(slen--)
        {
            if((len & 7) == 0) str[pos] = '\0';
            if(bit)
                str[pos] |= 0x80 >> (len & 7);
            if(!(++len & 7) && ++pos == 128)
                hc->f_h((unsigned char*)str,
                        1024 / ((hc->h_n & BITS) ? 1 : 8), hc->cx), pos = 0;
        }
        bit = 1 - bit;
    }

    if(len & 1023)
        hc->f_h((unsigned char*)str,
                        (len & 1023) / ((hc->h_n & BITS) ? 1 : 8), hc->cx);
    hc->f_e((unsigned char*)h, hc->cx);
    l = get_token(chr, 16, f);
    if(l != 1 || !token_is(chr, l, "^"))
        return (l < 1 ? l : 0);
    return 1;
}

int input_hash(char h[], FILE *f)
{   int k;
    char tok[128];

    k = get_token(tok, 128, f);
    if(k < 1 || k == 2 && token_is(tok, k, "<D"))
        return 0;
    if(token_to_hex(tok, k, h) >= 0)
    {
        k = get_token(tok, 32, f);
        if(k == 1 || token_is(tok, k, "^"))
            return 1;
    }
    return (k < 1 ? k : 0);
}

int do_header(FILE* fm, FILE *fo)
{   char   tok[32];
    int             n, k;

    n = out_text(fm, 0);

    do
    {
        k = get_token(tok, 32, fm);
    }
    while
        (k && !token_is(tok, k, "D>"));

    return n;
}

void out_header(FILE *fo, enum test t, int n, hash_ctx hc[1])
{
    fprintf(fo, "\n------------------------------------------");
    switch(t)
    {
    case basic_byte:    fprintf(fo, t_name[0]); break;
    case cs_bytes:      fprintf(fo, t_name[1], n); break;
    case cs_bits:       fprintf(fo, t_name[2], n); break;
    case gg_easy_by:    fprintf(fo, t_name[3], "bytes"); break;
    case gg_hard_by:    fprintf(fo, t_name[4], "bytes"); break;
    case gg_easy_bi:    fprintf(fo, t_name[3], "bits"); break;
    case gg_hard_bi:    fprintf(fo, t_name[4], "bits"); break;
    }
    fprintf(fo, "\nAlgorithm: %s (%s)", h_name[hc->h_n & 7],
                        h_name[(hc->h_n & 24) == BITS ? 6 : 7]);
    fprintf(fo, "\n------------------------------------------");
}

void do_type12(FILE* fm, FILE *fo, enum test t, hash_ctx hc[1])
{   char   h1[SHA2_MAX_DIGEST_SIZE];
    int             n;

    n = do_header(fm, fo);
    out_header(fo, t, n, hc);

    while(get_bitstr_hash(h1, fm, hc) && fo)
        hash_out(h1, hc->h_len, 0, fo);

    fprintf(fo, "\n");
}

void do_type3(FILE* fm, FILE *fo, enum test t, hash_ctx hc[1])
{   char   h1[SHA2_MAX_DIGEST_SIZE + 32];
    int             i, j, k, l;

    i = do_header(fm, fo);
    out_header(fo, t, i, hc);

    l = get_bitstr(h1, fm);
    if(l < 1)
        return;

    for(i = 0; i < 100; ++i)
    {
        for(j = 1; j <= 50000; ++j)
        {
            for(k = 0; k < 8 * (i / 4 + 3); ++k,++l)
            {
                if((l & 7) == 0) h1[l >> 3] = '\0';
                h1[l >> 3] &= (0x80 >> (l & 7));
            }

            for(k = 0; k < 32; ++k, ++l)
            {
                if((l & 7) == 0) h1[l >> 3] = '\0';
                h1[l >> 3] |= (((j >> (31 - k)) & 1) << (7 - (l & 7)));
            }

            hc->f_b(hc->cx);
            hc->f_h((unsigned char*)h1, l / ((hc->h_n & BITS) ? 1 : 8), hc->cx);
            hc->f_e((unsigned char*)h1, hc->cx);
            l = 8 * hc->h_len;
        }

        if(fo)
            hash_out(h1, SHA1_DIGEST_SIZE, 0, fo);
    }
    fprintf(fo, "\n");
}

char *csin_name(enum test t, char name[])
{   char *htype = (t == cs_bits ? "bit" : "byte");

    strcpy(name, in_file_prefix);
    strcat(name, htype);
    return name;
}

void do_messages(FILE *fo, enum test t, hash_ctx hc[1])
{   FILE    *fm;
    char    name[64];

    if(fm = fopen(csin_name(t, name), "r"))
    {
        do_type12(fm, fo, t, hc);
        do_type12(fm, fo, t, hc);
        do_type3(fm, fo, t, hc);
        fclose(fm);
    }
}

void do_bit_v1(FILE *fo, enum test t, hash_ctx hc[1])
{   unsigned char h1[SHA2_MAX_DIGEST_SIZE], h2[SHA2_MAX_DIGEST_SIZE], buf[128];
    int i, j, k, l, m, len;
    bit1_str *v;

    out_header(fo, t, 0, hc);

    if(t == gg_easy_by)
        v = bit1_gge, len = 12;
    else if(t == gg_hard_by)
        v = bit1_ggh, len = 8;
    else
        return;

    for(i = 0; i < len; ++i)
    {
        l = m = 0;
        hc->f_b(hc->cx);
        for(j = 0; j < v[i].rep_cnt; ++j)
            for(k = 0; k < 3; ++k)
            {
                buf[m] = v[i].rep_bytes[k]; l += 8;
                if(++m == 128)
                    hc->f_h(buf, 1024, hc->cx), m = 0;
            }
        for(k = 0; v[i].end_bits[k]; ++k)
        {
            buf[m] = (buf[m] << 1) | (v[i].end_bits[k] == '1' ? 1 : 0);
            if(!(++l & 7) && ++m == 128)
            {
                hc->f_h(buf, 1024, hc->cx); m = 0;
            }
        }

        if(l & 7) buf[m] <<= (8 - (l & 7));
        hc->f_h(buf, l & 1023, hc->cx);
        hc->f_e(h1, hc->cx);
        token_to_hex(v[i].hash, 120, (char*)h2);
        hash_out((char*)h1, hc->h_len, memcmp(h1, h2, hc->h_len), fo);
    }
    fprintf(fo, "\n");
}

void do_bit_v2(FILE *fo, enum test t, hash_ctx hc[1])
{   unsigned char h1[SHA2_MAX_DIGEST_SIZE], h2[SHA2_MAX_DIGEST_SIZE];
    int i, j, k, l, m, len;
    bit2_str *v;

    out_header(fo, t, 0, hc);

    if(t == gg_easy_bi)
        v = bit2_gge, len = 12;
    else if(t == gg_hard_bi)
        v = bit2_ggh, len = 8;
    else
        return;

    for(i = 0; i < len; ++i)
    {
        hc->f_b(hc->cx);
        for(j = 0; j < v[i].rep_cnt; ++j)
            hc->f_h((unsigned char*)&(v[i].rep_byte), 3, hc->cx);

        k = 0x80; l = m = 0;
        for(j = 0; v[i].end_bits[j]; ++j)
        {
            if(v[i].end_bits[j] == '1')
                m |= k;
            k >>= 1; ++l;
        }

        hc->f_h((unsigned char*)&m, l, hc->cx);
        hc->f_e(h1, hc->cx);
        token_to_hex(v[i].hash, 120, (char*)h2);
        hash_out((char*)h1, hc->h_len, memcmp(h1, h2, hc->h_len), fo);
    }
    fprintf(fo, "\n");
}

void do_vecs(FILE *fo, hash_ctx hc[1])
{   char h1[SHA2_MAX_DIGEST_SIZE], h2[SHA2_MAX_DIGEST_SIZE];
    int i, l, n;

    out_header(fo, basic_byte, 0, hc);
    for(i = 0; i < 6; ++i)
    {   l = (unsigned int)strlen(byte_v1[i].str[0]);
        n = (i == 5 ? 100000000 : i == 4 ? 1000000 : 50) / 50;
#if 0
        if(l > 70)
        {   strncpy(tstr, byte_v1[i].str[0], 70); tstr[70] = '\0';
            fprintf(fo, "\n%40s ...", tstr);
        }
        else
            fprintf(fo, "\n%s", byte_v1[i].str[0]);

        if(i == 4)
            fprintf(fo, " .. 1,000,000 characters");
        if(i == 5)
            fprintf(fo, " .. 100,000,000 characters");
#endif
        hc->f_b(hc->cx);
        while(n--)
            hc->f_h((unsigned char*)byte_v1[i].str[0],
                        ((hc->h_n & BITS) ? 8 : 1) * l, hc->cx);
        hc->f_e((unsigned char*)h1, hc->cx);
        token_to_hex(byte_v1[i].str[hc->h_n & 7],
                        (int)strlen(byte_v1[i].str[hc->h_n & 7]), h2);
        hash_out(h1, hc->h_len, memcmp(h1, h2, hc->h_len), fo);
    }
    fprintf(fo, "\n");
}

void do_vecs_fips_180_4(FILE *fo)
{   char h[SHA2_MAX_DIGEST_SIZE];
    int i, l, n;

    for(i = 0; i < 2; ++i)
    {   l = (int)strlen(byte_v2[i].str);
        memset(h, 0, sizeof(h));
        sha512_224(h, byte_v2[i].str, l);
        n = memcmp(h, byte_v2[i].sha512_224, 224 >> 3);
        if(n != 0)
            fprintf(fo, "\nSHA-512/224 failed for input \"%s\"", byte_v2[i].str);
        else
            fprintf(fo, "\nSHA-512/224 succeeded for input \"%s\"", byte_v2[i].str);
        memset(h, 0, sizeof(h));
        sha512_256(h, byte_v2[i].str, l);
        n = memcmp(h, byte_v2[i].sha512_256, 256 >> 3);
        if(n != 0)
            fprintf(fo, "\nSHA-512/256 failed for input \"%s\"", byte_v2[i].str);
        else
            fprintf(fo, "\nSHA-512/256 succeeded for input \"%s\"", byte_v2[i].str);
    }
    fprintf(fo, "\n");
}

void do_tests(FILE *fo, enum hash alg, enum test t)
{   hash_ctx      hc[1];

    hc->h_n = alg;
    switch(alg & 7)
    {
    case SHA1:
        hc->h_len = SHA1_DIGEST_SIZE;
        hc->f_b = (f_begin)sha1_begin;
        hc->f_h = (f_hash)sha1_hash;
        hc->f_e = (f_end)sha1_end;
        break;
    case SHA224:
        hc->h_len = SHA224_DIGEST_SIZE;
        hc->f_b = (f_begin)sha224_begin;
        hc->f_h = (f_hash)sha224_hash;
        hc->f_e = (f_end)sha224_end;
        break;
    case SHA256:
        hc->h_len = SHA256_DIGEST_SIZE;
        hc->f_b = (f_begin)sha256_begin;
        hc->f_h = (f_hash)sha256_hash;
        hc->f_e = (f_end)sha256_end;
        break;
#ifdef SHA_64BIT
    case SHA384:
        hc->h_len = SHA384_DIGEST_SIZE;
        hc->f_b = (f_begin)sha384_begin;
        hc->f_h = (f_hash)sha384_hash;
        hc->f_e = (f_end)sha384_end;
        break;
    case SHA512:
        hc->h_len = SHA512_DIGEST_SIZE;
        hc->f_b = (f_begin)sha512_begin;
        hc->f_h = (f_hash)sha512_hash;
        hc->f_e = (f_end)sha512_end;
        break;
#endif
    }

    if(t & basic_byte) do_vecs(fo, hc);
    if(alg & BITS)
    {
        if(t & gg_easy_by) do_bit_v1(fo, gg_easy_by, hc);
        if(t & gg_hard_by) do_bit_v1(fo, gg_hard_by, hc);
        if(t & gg_easy_bi) do_bit_v2(fo, gg_easy_bi, hc);
        if(t & gg_hard_bi) do_bit_v2(fo, gg_hard_bi, hc);
        if(t & cs_bits) do_messages(fo, cs_bits, hc);
    }
    if(t & cs_bytes) do_messages(fo, cs_bytes, hc);
}

char *csout_name(enum hash h, char name[])
{
    strcpy(name, out_file_prefix);
    strcat(name, h_name[h & 7]);
    strcat(name, ((h & BITS) ? ".bits" : ".byte"));
    return name;
}

int main(void)
{   FILE    *fo;
    enum hash alg;
    enum hash bits = 0;
    enum test tests;

/*  tests = basic_byte | cs_bits | cs_bytes | gg_easy_bi | gg_hard_bi;  */

#ifdef TO_CONSOLE

    fo = stdout;
    tests = basic_byte;

#if defined(TEST_SHA1)
    alg = SHA1 | (SHA1_BITS ? BITS : 0);
    do_tests(fo, alg, tests);
#endif
#if defined(TEST_SHA224)
    alg = SHA224 | (SHA2_BITS ? BITS : 0);
    do_tests(fo, alg, tests);
#endif
#if defined(TEST_SHA256)
    alg = SHA256 | (SHA2_BITS ? BITS : 0);
    do_tests(fo, alg, tests);
#endif
#if defined(TEST_SHA384)
    alg = SHA384 | (SHA2_BITS ? BITS : 0);
    do_tests(fo, alg, tests);
#endif
#if defined(TEST_SHA512)
    alg = SHA512 | (SHA2_BITS ? BITS : 0);
    do_tests(fo, alg, tests);
    do_vecs_fips_180_4(fo);
#endif

#else

    tests = basic_byte | cs_bits | cs_bytes | gg_easy_bi | gg_hard_bi;

#if defined(TEST_SHA1)
    alg = SHA1 | (SHA1_BITS ? BITS : 0);
    fo = fopen(csout_name(alg, name), "w");
    do_tests(fo, alg, tests);
    fclose(fo);
#endif
#if defined(TEST_SHA224)
    alg = SHA224 | (SHA2_BITS ? BITS : 0);
    fo = fopen(csout_name(alg, name), "w");
    do_tests(fo, alg, tests);
    fclose(fo);
#endif
#if defined(TEST_SHA256)
    alg = SHA256 | (SHA2_BITS ? BITS : 0);
    fo = fopen(csout_name(alg, name), "w");
    do_tests(fo, alg, tests);
    fclose(fo);
#endif
#if defined(TEST_SHA384)
    alg = SHA384 | (SHA2_BITS ? BITS : 0);
    fo = fopen(csout_name(alg, name), "w");
    do_tests(fo, alg, tests);
    fclose(fo);
#endif
#if defined(TEST_SHA512)
    alg = SHA512 | (SHA2_BITS ? BITS : 0);
    fo = fopen(csout_name(alg, name), "w");
    do_tests(fo, alg, tests);
    fclose(fo);
#endif

#endif

    return 0;
}
