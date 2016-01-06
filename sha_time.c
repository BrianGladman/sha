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

#define DUAL_CORE

#if defined( DUAL_CORE )
#include <windows.h>
#endif
#include <stdio.h>
#include <memory.h>

#include "rdtsc.h"
#include "sha1.h"
#include "sha2.h"

#if SHA1_BITS == 0 && SHA2_BITS == 0 
#  define SHA_TIME_BYTES
#elif SHA1_BITS == 1 && SHA2_BITS == 1
#  define SHA_TIME_BITS
#else
#  error SHA1 and SHA2 must both be bit orientated or both byte oriented
#endif

enum hash        {    SHA2 = 0,   SHA1 = 1, SHA224 = 2, SHA256 =  3,
                    SHA384 = 4, SHA512 = 5,   BITS = 8,  BYTES = 16 };

char *h_name[] = { "sha2", "sha1", "sha224", "sha256", "sha384", "sha512",
                   "bits", "bytes" };

#if defined(__cplusplus)
extern "C"
{
#endif

typedef void (*f_begin)(void* cx);
typedef void (*f_hash)(const unsigned char d[], unsigned long l, void* cx);
typedef void (*f_end)(unsigned char h[], void* cx);

#if defined(__cplusplus)
}
#endif

typedef union
{   sha1_ctx  cx1;
    sha2_ctx  cx2;
} u_ctx;

typedef struct
{   enum hash    h_n;
    unsigned int hlen;
    u_ctx        cx[1];
    f_begin      f_b;
    f_hash       f_h;
    f_end        f_e;
} hash_ctx;

#define  PROCESSOR   "PIV"  // Processor

const unsigned int loops = 100; // number of timing loops

unsigned int rand32(void)
{   static unsigned int   r4,r_cnt = -1,w = 521288629,z = 362436069;

    z = 36969 * (z & 65535) + (z >> 16);
    w = 18000 * (w & 65535) + (w >> 16);

    r_cnt = 0; r4 = (z << 16) + w; return r4;
}

unsigned char rand8(void)
{   static unsigned int   r4,r_cnt = 4;

    if(r_cnt == 4)
    {
        r4 = rand32(); r_cnt = 0;
    }

    return (char)(r4 >> (8 * r_cnt++));
}

// fill a block with random charactrers

void block_rndfill(unsigned char l[], unsigned int len)
{   unsigned int  i;

    for(i = 0; i < len; ++i)

        l[i] = rand8();
}

unsigned int do_cycles(const unsigned char buf[], unsigned int len, enum hash alg)
{   hash_ctx        hc[1];
    unsigned char   hv[SHA2_MAX_DIGEST_SIZE];
    unsigned int    i, c1 = -1, c2 = -1;
    unsigned volatile long long cy0, cy1, cy2;

    hc->h_n = alg;

    switch(alg & 7)
    {
    case SHA1:
        hc->hlen = SHA1_DIGEST_SIZE;
        hc->f_b = (f_begin)sha1_begin;
        hc->f_h = (f_hash)sha1_hash;
        hc->f_e = (f_end)sha1_end;
        break;
    case SHA224:
        hc->hlen = SHA224_DIGEST_SIZE;
        hc->f_b = (f_begin)sha224_begin;
        hc->f_h = (f_hash)sha224_hash;
        hc->f_e = (f_end)sha224_end;
        break;
    case SHA256:
        hc->hlen = SHA256_DIGEST_SIZE;
        hc->f_b = (f_begin)sha256_begin;
        hc->f_h = (f_hash)sha256_hash;
        hc->f_e = (f_end)sha256_end;
        break;
#ifdef SHA_64BIT
    case SHA384:
        hc->hlen = SHA384_DIGEST_SIZE;
        hc->f_b = (f_begin)sha384_begin;
        hc->f_h = (f_hash)sha384_hash;
        hc->f_e = (f_end)sha384_end;
        break;
    case SHA512:
        hc->hlen = SHA512_DIGEST_SIZE;
        hc->f_b = (f_begin)sha512_begin;
        hc->f_h = (f_hash)sha512_hash;
        hc->f_e = (f_end)sha512_end;
        break;
#endif
    }

    hc->f_b(hc->cx);
    hc->f_h(buf, len, hc->cx);
    hc->f_e(hv, hc->cx);

    for(i = 0; i < loops; ++i)
    {
        cy0 = read_tsc();

        hc->f_b(hc->cx);
        hc->f_h(buf, len, hc->cx);
        hc->f_e(hv, hc->cx);

        cy1 = read_tsc();

        hc->f_b(hc->cx);
        hc->f_h(buf, len, hc->cx);
        hc->f_e(hv, hc->cx);

        hc->f_b(hc->cx);
        hc->f_h(buf, len, hc->cx);
        hc->f_e(hv, hc->cx);

        cy2 = read_tsc();

        cy2 -= cy1; cy1 -= cy0;
        c1 = (unsigned int)(c1 > cy1 ? cy1 : c1);
        c2 = (unsigned int)(c2 > cy2 ? cy2 : c2);
    }
    return ((c2 - c1) + 1);
}

unsigned char   buf[125000];

#ifdef SHA_64BIT
#define TESTS_HI 6
#else
#define TESTS_HI 4
#endif

int main(void)
{   double t;
    int i, n;

#if defined( DUAL_CORE ) && defined( _WIN32 )
	// we need to constrain the process to one core in order to 
	// obtain meaningful timing data
	HANDLE ph;
	DWORD_PTR afp;
	DWORD_PTR afs;
	ph = GetCurrentProcess();
	if(GetProcessAffinityMask(ph, &afp, &afs))
	{
		afp &= (GetCurrentProcessorNumber() + 1);
		if(!SetProcessAffinityMask(ph, afp))
		{
			printf("Couldn't set Process Affinity Mask\n\n"); return -1;
		}
	}
	else
	{
		printf("Couldn't get Process Affinity Mask\n\n"); return -1;
	}
#endif

#ifdef SHA_TIME_BITS
#define STR  "Bit"
#define MUL     10
#else
#define STR "Byte"
#define MUL     1
#endif

    block_rndfill(buf, 125000);

    printf("\n");
    printf("\nSHA1/SHA2 Performance in Cycles/%s Versus Message Length", STR);
#ifdef SHA_TIME_BITS
    printf("\nLength (bits)    1      10     100    1000   10000  100000 1000000");
#else
    printf("\nLength (bytes)   1      10     100    1000   10000  100000");
#endif
    for(n = 1; n < TESTS_HI; ++n)
    {
        printf("\n%-8s  ", h_name[n]);
        for(i = 1; i <= 100000 * MUL; i *= 10)
        {
            t = do_cycles(buf, i, (enum hash)n) / (double)i;
            printf("%8.2f", t);
        }
    }

    printf("\n\n");
    return 0;
}
