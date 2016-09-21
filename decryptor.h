#pragma once

#include "types.h"
#include <string>

bool decrypt(const uint8_t* iv, const ByteBuff& checkBuff, char* outKey, size_t outKeyLen);
bool verifyKey(const std::string& key, std::string* lpExpandedCleanKey16);
size_t unmatching_count(ByteBuff bf);
