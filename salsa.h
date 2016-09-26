/**
Original: https://github.com/alexwebr/salsa20
*/
#ifndef _SALSA20_H_
#define _SALSA20_H_

#include <stdint.h>
#include <stddef.h>

bool s20_crypt_256bit(const uint8_t *key,
    const uint8_t nonce[8],
    uint32_t si,
    uint8_t *buf,
    uint32_t buflen);

#endif
