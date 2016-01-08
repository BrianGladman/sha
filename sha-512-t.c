/*
---------------------------------------------------------------------------
Copyright (c) 2016, Michael Mohr, California, US. All rights reserved.

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
Issue Date: 07 Jan 2016

This is a program which can be used to pre-calculate SHA-512/t IVs.
  For more info: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
*/

#include <stdio.h>
#include <inttypes.h>
#include <endian.h>

#include "sha2.h"

const char *truncated_names[4] = {
    "SHA-512/256",
    "SHA-512/224",
    "SHA-512/192",
    "SHA-512/128",
};

int main(int argc, char **argv) {
    unsigned int i, j;
    sha512_ctx cx[1];
    union {
        uint64_t qwords[8];
        uint8_t bytes[SHA512_DIGEST_SIZE];
    } hval;

    for(i=0; i<4; i++) {
        printf("/* FIPS PUB 180-4: %s */\nconst uint64_t i512_xxx[8] =\n{", truncated_names[i]);
        sha512_begin(cx);
        for(j=0; j<8; j++)
            cx[0].hash[j] ^= be64toh(0xa5a5a5a5a5a5a5a5);
        sha512_hash((const unsigned char *)truncated_names[i], 11, cx);
        sha512_end(hval.bytes, cx);
        for(j=0; j<8; j++) {
            if(((j % 2) == 0))
                printf("\n    ");
            printf("li_64(%016lx), ", htobe64(hval.qwords[j]));
        }
        printf("\n};\n\n");
    }
}
