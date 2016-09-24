/**
Original: https://github.com/alexwebr/salsa20
WARNING: This is a vulnerable version (from Petya v2 - Green)
*/
#ifndef _SALSA20_H_
#define _SALSA20_H_

#include <stdint.h>
#include <stddef.h>

enum s20_status_t
{
  S20_SUCCESS,
  S20_FAILURE
};

enum s20_keylen_t
{
  S20_KEYLEN_256,
  S20_KEYLEN_128
};


enum s20_status_t s20_crypt(uint8_t *key,
                            enum s20_keylen_t keylen,
                            uint8_t nonce[8],
                            uint32_t si,
                            uint8_t *buf,
                            uint32_t buflen);

#endif

