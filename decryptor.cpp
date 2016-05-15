// Author of implementation: AlexWMF
// Author of the idea: leo-stone
// Genetic algorithm taken from https://github.com/handcraftsman/GeneticPy

#include "decryptor.h"
#include "genetic.h"

#include <iostream>
#include <string>
#include <stdint.h>
#include <memory.h>
#include <vector>


namespace {

static const std::string kPetyaCharset = "123456789abcdefghijkmnopqrstuvwxABCDEFGHJKLMNPQRSTUVWX";

static const unsigned char kBitsSetTable256[256] =
{
#   define B2(n) n,     n+1,     n+1,     n+2
#   define B4(n) B2(n), B2(n+1), B2(n+1), B2(n+2)
#   define B6(n) B4(n), B4(n+1), B4(n+1), B4(n+2)
    B6(0), B6(1), B6(1), B6(2)
};


static uint16_t rotl(uint16_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

void s20_quarterround(uint16_t *y0, uint16_t *y1, uint16_t *y2, uint16_t *y3)
{
    *y1 = *y1 ^ rotl(*y0 + *y3, 7);
    *y2 = *y2 ^ rotl(*y1 + *y0, 9);
    *y3 = *y3 ^ rotl(*y2 + *y1, 13);
    *y0 = *y0 ^ rotl(*y3 + *y2, 18);
}

uint16_t s20_littleendian16(uint8_t *b)
{
    return b[0] + (b[1] << 8);
}

void s20_rev_littleendian_orig(uint8_t *b, uint32_t w)
{
    b[0] = w;
    b[1] = w >> 8;
    b[2] = w >> 16;
    b[3] = w >> 24;
}

void s20_doubleround(uint16_t x[16])
{
    // s20_columnround(x);
    s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
    s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
    s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
    s20_quarterround(&x[15], &x[3], &x[7], &x[11]);

    //s20_rowround(x);
    s20_quarterround(&x[0], &x[1], &x[2], &x[3]);
    s20_quarterround(&x[5], &x[6], &x[7], &x[4]);
    s20_quarterround(&x[10], &x[11], &x[8], &x[9]);
    s20_quarterround(&x[15], &x[12], &x[13], &x[14]);
}

void s20_hash(uint8_t seq[64])
{
    int i;
    uint16_t x[16];
    uint16_t z[16];

    // Create two copies of the state in little-endian format
    // First copy is hashed together
    // Second copy is added to first, word-by-word
    for (i = 0; i < 16; ++i)
        x[i] = z[i] = s20_littleendian16(seq + (4 * i));

    for (i = 0; i < 10; ++i)
    {
        s20_doubleround(z);
    }

    for (i = 0; i < 16; ++i) {
        z[i] += x[i];
        s20_rev_littleendian_orig(seq + (4 * i), z[i]);
    }
}

void s20_expand32_orig(const uint8_t *k, uint8_t n[16], uint8_t keystream[64])
{
    int i, j;
    // The constants specified by the Salsa20 specification, 'sigma'
    // "expand 32-byte k"
    uint8_t o[4][4] = {
            { 'e', 'x', 'p', 'a' },
            { 'n', 'd', ' ', '3' },
            { '2', '-', 'b', 'y' },
            { 't', 'e', ' ', 'k' }
    };

    // Copy all of 'sigma' into the correct spots in our keystream block
    for (i = 0; i < 64; i += 20)
        for (j = 0; j < 4; ++j)
            keystream[i + j] = o[i / 20][j];

    // Copy the key and the nonce into the keystream block
    for (i = 0; i < 16; ++i) {
        keystream[4 + i] = k[i];
        keystream[44 + i] = k[i + 16];
        keystream[24 + i] = n[i];
    }

    s20_hash(keystream);
}

bool s20_crypt_orig_256bit(const uint8_t *key, const uint8_t nonce[8], uint32_t si, uint8_t *buf, uint32_t buflen)
{
    uint8_t keystream[64];
    // 'n' is the 8-byte nonce (unique message number) concatenated
    // with the per-block 'counter' value (4 bytes in our case, 8 bytes
    // in the standard). We leave the high 4 bytes set to zero because
    // we permit only a 32-bit integer for stream index and length.
    uint8_t n[16] = { 0 };
    uint32_t i;

    // If any of the parameters we received are invalid
    if (key == NULL || nonce == NULL || buf == NULL)
        return false;

    // Set up the low 8 bytes of n with the unique message number
    for (i = 0; i < 8; ++i)
        n[i] = nonce[i];

    // If we're not on a block boundary, compute the first keystream
    // block. This will make the primary loop (below) cleaner
    if (si % 64 != 0) {
        // Set the second-to-highest 4 bytes of n to the block number
        s20_rev_littleendian_orig(n + 8, si / 64);
        // Expand the key with n and hash to produce a keystream block
        s20_expand32_orig(key, n, keystream);
    }

    // Walk over the plaintext byte-by-byte, xoring the keystream with
    // the plaintext and producing new keystream blocks as needed
    for (i = 0; i < buflen; ++i) {
        // If we've used up our entire keystream block (or have just begun
        // and happen to be on a block boundary), produce keystream block
        if ((si + i) % 64 == 0) {
            s20_rev_littleendian_orig(n + 8, ((si + i) / 64));
            s20_expand32_orig(key, n, keystream);
        }

        // xor one byte of plaintext with one byte of keystream
        buf[i] ^= keystream[(si + i) % 64];
    }

    return true;
}


class PetyaDecryptor
{
public:
    PetyaDecryptor(const uint8_t iv[IV_LEN], const ByteBuff& check)
            : check_(check)
            , xorBuff_(check)
            , currXorBuffIdx_(0)
    {
        memset(&key_, 0, sizeof(key_));

        key_.expa[0] = 'e';
        key_.expa[1] = 'x';
        key_.expa[2] = 'p';
        key_.expa[3] = 'a';

        key_.nd3[0] = 'n';
        key_.nd3[1] = 'd';
        key_.nd3[2] = ' ';
        key_.nd3[3] = '3';

        key_.twoby[0] = '2';
        key_.twoby[1] = '-';
        key_.twoby[2] = 'b';
        key_.twoby[3] = 'y';

        key_.tek[0] = 't';
        key_.tek[1] = 'e';
        key_.tek[2] = ' ';
        key_.tek[3] = 'k';

        memcpy(key_.iv, iv, IV_LEN);

        for (size_t i = 0, e = xorBuff_.size(); i < e; ++i)
            xorBuff_[i] ^= 0x37;
    }

    std::vector<uint16_t> getNthXorBuff(size_t n) const
    {
        const size_t offset = n * SALSA20_KEYSTREAM_CHUNK_SIZE;
        std::vector<uint16_t> rv(BLOCK_SIZE_SHORTS, 0);
        const uint16_t* p = reinterpret_cast<const uint16_t*>(&xorBuff_[0] + offset);
        for (int i = 0; i < BLOCK_SIZE_SHORTS; ++i, p += 2)
            rv[i] = *p;
        return rv;
    }

    static void fillKey(Salsa20KeyBuff& key, uint8_t ch1, uint8_t ch2, uint8_t ch3, uint8_t ch4, uint8_t ch5, uint8_t ch6, uint8_t ch7, uint8_t ch8)
    {
        key.keyPart1[0 + 0] = ch1 + 0x7a;
        key.keyPart1[0 + 1] = ch1 * 2;

        key.keyPart1[4 + 0] = ch2 + 0x7a;
        key.keyPart1[4 + 1] = ch2 * 2;

        key.keyPart1[8 + 0] = ch3 + 0x7a;
        key.keyPart1[8 + 1] = ch3 * 2;

        key.keyPart1[12 + 0] = ch4 + 0x7a;
        key.keyPart1[12 + 1] = ch4 * 2;

        key.keyPart2[0 + 0] = ch5 + 0x7a;
        key.keyPart2[0 + 1] = ch5 * 2;

        key.keyPart2[4 + 0] = ch6 + 0x7a;
        key.keyPart2[4 + 1] = ch6 * 2;

        key.keyPart2[8 + 0] = ch7 + 0x7a;
        key.keyPart2[8 + 1] = ch7 * 2;

        key.keyPart2[12 + 0] = ch8 + 0x7a;
        key.keyPart2[12 + 1] = ch8 * 2;
    }

    static int getBitDiff(const uint8_t* bf1, const uint8_t* bf2, int len)
    {
        int rv = 0;
        for (int i = 0; i < len; ++i, ++bf1, ++bf2)
            rv += kBitsSetTable256[*bf1 ^ *bf2];
        return rv;
    }

    bool brute()
    {
        currXorBuff_ = getNthXorBuff(0);

        auto fnGetFitness = [this](const std::string& genes)
        {
            fillKey(key_, genes[0], genes[1], genes[2], genes[3], genes[4], genes[5], genes[6],
                    genes[7]);

            std::vector<uint16_t> tmp(BLOCK_SIZE_SHORTS, 0);
            const uint16_t* etalon = reinterpret_cast<uint16_t*>(&key_);
            std::vector<uint16_t> z(BLOCK_SIZE_SHORTS, 0);

            for (int i = 0; i < BLOCK_SIZE_SHORTS; ++i, etalon += 2)
            {
                z[i] = *etalon;
                tmp[i] = currXorBuff_[i] - *etalon;
            }

            for (int i = 0; i < 10; ++i)
                s20_doubleround(&z[0]);

            return getBitDiff(reinterpret_cast<const uint8_t*>(&z[0]), reinterpret_cast<const uint8_t*>(&tmp[0]),
                              BLOCK_SIZE_SHORTS * sizeof(uint16_t));
        };

        auto fnIsBetter = [](int oldFitness, int newFitness) {
            return newFitness < oldFitness;
        };

        auto fnIsFinished = [](int fitness) {
            return fitness <= 0;
        };

        GeneticSolver solver {kPetyaCharset, KEY_LEN, 128, fnGetFitness, fnIsFinished, fnIsBetter};
        std::string key;
        solver.brute(key);

        printf("[+] Key generation finished\n");
        std::string result;
        const bool ok = verifyKey(key, &result);
        if (ok)
            printf("[+] YOUR KEY: %s\n", result.c_str());

        return ok;
    }

    bool verifyKey(const std::string& key, std::string* lpExpandedCleanKey16) const
    {
        const char padding_char = 'x';
        std::string cleanKey16 = key;
        for (int i = 0; i < KEY_LEN; ++i)
            cleanKey16.insert(cleanKey16.begin() + KEY_LEN - i, padding_char);

        if (lpExpandedCleanKey16)
            *lpExpandedCleanKey16 = cleanKey16;

        std::vector<uint8_t> fullPetyaKey(EXPANDED_KEY_LENGTH, 0);
        for (unsigned i = 0; i < cleanKey16.size(); ++i)
        {
            fullPetyaKey[i * 2 + 0] = uint8_t(cleanKey16[i]) + 0x7a;
            fullPetyaKey[i * 2 + 1] = uint8_t(cleanKey16[i]) * 2;
        }

        ByteBuff bf(check_);
        s20_crypt_orig_256bit(&fullPetyaKey[0], key_.iv, 0, &bf[0], static_cast<uint32_t>(bf.size()));

        for (char c : bf)
        {
            if (c != '7')
            {
                printf("[-] Validation failed\n");
                return false;
            }
        }
        printf("[+] Validation passed\n");
        return true;
    }

private:
    Salsa20KeyBuff key_;
    ByteBuff check_;
    ByteBuff xorBuff_;
    std::vector<uint16_t> currXorBuff_;
    int currXorBuffIdx_;

};

} // anonymous



bool decrypt(const uint8_t* iv, const ByteBuff& checkBuff, char* outKey, size_t outKeyLen)
{
    PetyaDecryptor decryptor(iv, checkBuff);
    const bool ok = decryptor.brute();
    return ok;
}
