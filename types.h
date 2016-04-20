#ifndef PETYA_RECOVERY_TYPES_H
#define PETYA_RECOVERY_TYPES_H
// Author: AlexWMF

#include <stdint.h>
#include <stdlib.h>
#include <vector>

#if defined(_MSC_VER)
#   define ALIGNED_(x) __declspec(align(x))
#else
#   if defined(__GNUC__)
#       define ALIGNED_(x) __attribute__ ((aligned(x)))
#   endif
#endif


#define SECTOR_SIZE 0x200
#define KEY_LEN 8
#define PLAIN_KEY_LENGTH 16
#define EXPANDED_KEY_LENGTH 32
#define BLOCK_SIZE_SHORTS 16
#define IV_LEN 8
#define CHECK_BUFFER_SECTOR_NUM 55
#define ONION_SECTOR_NUM 54
#define SALSA20_KEYSTREAM_CHUNK_SIZE 64


struct ALIGNED_(1) Salsa20KeyBuff
{
    uint8_t expa[4];        // +00h: = 'e', 'x', 'p', 'a'
    uint8_t keyPart1[16];   // +04h:
    uint8_t nd3[4];         // +14h: = 'n', 'd', ' ', '3'
    uint8_t iv[IV_LEN];     // +18h:
    uint32_t streamPosition;// +20h;
    uint8_t zeros[4];       // +24h:
    uint8_t twoby[4];       // +28h: = '2', '-', 'b', 'y'
    uint8_t keyPart2[16];   // +2Ch:
    uint8_t tek[4];         // +3Ch: = 't', 'e', ' ', 'k'
};
static_assert(sizeof(Salsa20KeyBuff) == SALSA20_KEYSTREAM_CHUNK_SIZE, "Invalid struct Salsa20KeyBuff alignment");


struct ALIGNED_(1) OnionSector
{
    enum State : uint8_t
    {
        ST_NotEncrypted = 0,
        ST_Encrypted = 1,
        ST_Decrypted = 2
    };
    State eEncrypted;                   // +00h
    uint8_t key[EXPANDED_KEY_LENGTH];   // +01h
    uint8_t iv[IV_LEN];                 // +21h
    char szURLs[128];                   // +29h
    char szPubKey[343];                 // +A9h
};
static_assert(sizeof(OnionSector) == SECTOR_SIZE, "Invalid struct OnionSector alignment");

typedef std::vector<uint8_t> ByteBuff;

#endif //PETYA_RECOVERY_TYPES_H
