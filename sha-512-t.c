/*
 *  sha-512-t.c - Copyright 2016, Michael Mohr
 *  Released under the GPL version 3.
 *  This is a quick hack that can be used to pre-calculate SHA-512/t IVs.
 *  See: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
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
