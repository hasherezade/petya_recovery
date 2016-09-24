#pragma once
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
#define EXPANDED_KEY_LENGTH 16
#define BLOCK_SIZE_SHORTS 16
#define IV_LEN 8
#define CHECK_BUFFER_SECTOR_NUM 55
#define ONION_SECTOR_NUM 54

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
    uint8_t padding[16];
    uint8_t iv[IV_LEN];                 // +21h
    char szURLs[128];                   // +29h
    char szPubKey[343];                 // +A9h
};

static_assert(sizeof(OnionSector) == SECTOR_SIZE, "Invalid struct OnionSector alignment");

typedef std::vector<uint8_t> ByteBuff;

