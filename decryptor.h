#ifndef PETYA_RECOVERY_DECRYPTOR_H
#define PETYA_RECOVERY_DECRYPTOR_H

#include "types.h"


bool decrypt(const uint8_t* iv, const ByteBuff& checkBuff, char* outKey, size_t outKeyLen);


#endif //PETYA_RECOVERY_DECRYPTOR_H
