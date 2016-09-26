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

#define VERIF_CHAR 0x37


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

    std::string makeUserKey(const std::string& key)
    {
        const char padding_char = 'x';
        std::string cleanKey16 = key;
        for (int i = 0; i < KEY_LEN; ++i)
            cleanKey16.insert(cleanKey16.begin() + KEY_LEN - i, padding_char);
        return cleanKey16;
    }

    std::vector<uint8_t> makeFullPetyaKey(const std::string& cleanKey16)
    {
        std::vector<uint8_t> fullPetyaKey(EXPANDED_KEY_LENGTH, 0);
        for (unsigned i = 0; i < cleanKey16.size(); ++i)
        {
            fullPetyaKey[i * 2 + 0] = uint8_t(cleanKey16[i]) + 0x7a;
            fullPetyaKey[i * 2 + 1] = uint8_t(cleanKey16[i]) * 2;
        }
        return fullPetyaKey;
    }

    size_t verifyKey(const std::string& key)
    {
        std::string cleanKey16 = makeUserKey(key);
        std::vector<uint8_t> fullPetyaKey = makeFullPetyaKey(cleanKey16);

        ByteBuff bf(check_);
        s20_crypt_256bit(&fullPetyaKey[0], iv_, 0, &bf[0], static_cast<uint32_t>(bf.size()));
        return unmatching_count(bf);
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
