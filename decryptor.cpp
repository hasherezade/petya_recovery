// Authors of the implementation: AlexWMF, hasherezade
// Author of the idea: leo-stone
// Genetic algorithm taken from https://github.com/handcraftsman/GeneticPy

#include "decryptor.h"
#include "salsa.h"
#include "genetic.h"

#include <iostream>
#include <string>
#include <stdint.h>
#include <memory.h>
#include <vector>

#define VERIF_CHAR 0x07

namespace {

static const std::string kPetyaCharset = "123456789abcdefghijkmnopqrstuvwxABCDEFGHJKLMNPQRSTUVWX";


class PetyaDecryptor
{
public:
    PetyaDecryptor(const uint8_t iv[IV_LEN], const ByteBuff& check)
        : check_(check)
    {
        memcpy(iv_, iv, IV_LEN);
    }

    bool brute()
    {
        auto fnGetFitness = [this](const std::string& genes)
        {
            size_t unmatching = verifyKey(genes);
            return unmatching;
        };

        auto fnIsBetter = [](int oldFitness, int newFitness) {
            return newFitness < oldFitness;
        };

        auto fnIsFinished = [](int fitness) {
            return fitness <= 0;
        };

        GeneticSolver solver {kPetyaCharset, KEY_LEN, 128, fnGetFitness, fnIsFinished, fnIsBetter};
        std::string key;
        if (solver.brute(key)) {
            printf("[+] Success!\n");
            std::string userKey = makeUserKey(key);
            printf("[+] Your key: %s\n", userKey.c_str());
            return true;
        }

        return false;
    }

    size_t unmatching_count(ByteBuff bf)
    {
        size_t unmatching = 0;
        for (char c : bf)
        {
            if (c != VERIF_CHAR) unmatching++;
        }
        return unmatching;
    }

    std::string makeUserKey(const std::string& keyStr)
    {
        const char padding_char = 'x';
        char key[EXPANDED_KEY_LENGTH + 1];
        memset(key, 'x', EXPANDED_KEY_LENGTH);

        for (int i = 0, j = 0; i < EXPANDED_KEY_LENGTH; i+=4, j+=2) {
            static size_t rand_i1 = 0;
            static size_t rand_i2 = 0;
            key[i] = keyStr[j];
            key[i+1] = keyStr[j+1];
        }
        key[EXPANDED_KEY_LENGTH] = 0;

        return key;
    }

    std::vector<uint8_t> makeFullPetyaKey(const std::string& cleanKey16)
    {
        std::vector<uint8_t> fullPetyaKey(EXPANDED_KEY_LENGTH, 0);
        for (unsigned i = 0; i < cleanKey16.size(); ++i)
        {
            fullPetyaKey[i] = uint8_t(cleanKey16[i]);
        }
        return fullPetyaKey;
    }

    size_t verifyKey(const std::string& key)
    {
        std::string cleanKey16 = makeUserKey(key);
        std::vector<uint8_t> fullPetyaKey = makeFullPetyaKey(cleanKey16);

        ByteBuff bf(check_);
        //printf("Key: %s\n", cleanKey16.c_str());
        if (s20_crypt(&fullPetyaKey[0], S20_KEYLEN_128, iv_, 0, &bf[0], bf.size()) == S20_FAILURE) {
            printf("[ERROR] Cannot encrypt!\n");
            return -1;
        }
        size_t count = unmatching_count(bf);
        //printf("unmatching: %d\n", count);
        return count;
    }

private:
    uint8_t iv_[IV_LEN];
    ByteBuff check_;
};

} // anonymous


bool decrypt(const uint8_t* iv, const ByteBuff& checkBuff, char* outKey, size_t outKeyLen)
{
    PetyaDecryptor decryptor(iv, checkBuff);
    const bool ok = decryptor.brute();
    return ok;
}
