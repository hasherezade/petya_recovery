// Petya recovery help
// by: hasherezade
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cstddef>
#include <cinttypes>
#include "base64.h"
#include "decryptor.h"
#include "types.h"


typedef unsigned char BYTE;

char out_buf[0x400];

bool check_pattern(FILE *fp, size_t offset, const char *cmp_buf, size_t cmp_size)
{
    cmp_size = (cmp_size > sizeof(out_buf)) ? sizeof(out_buf) : cmp_size;

    fseek(fp, offset, SEEK_SET);
    size_t read = fread(out_buf, 1, cmp_size, fp);

    if (read != cmp_size) {
        printf("Error, read = %d\n", read);
        return false;
    }

    if (memcmp(out_buf, cmp_buf, cmp_size-1) == 0) {
        return true;
    }
    return false;
}

bool is_infected(FILE *fp)
{
    char Bootloader[] = \
    "\xfa\x66\x31\xc0\x8e\xd0\x8e\xc0\x8e\xd8\xbc\x00\x7c\xfb\x88\x16"
    "\x93\x7c\x66\xb8\x20\x00\x00\x00\x66\xbb\x22\x00\x00\x00\xb9\x00"
    "\x80\xe8\x14\x00\x66\x48\x66\x83\xf8\x00\x75\xf5\x66\xa1\x00\x80"
    "\xea\x00\x80\x00\x00";

    const size_t bootloader_offset = 0;
    bool has_bootloader = check_pattern(fp, bootloader_offset, Bootloader, sizeof(Bootloader));
    if (has_bootloader) printf("[+] Petya bootloader detected!\n");

    char http_pattern[] = "http://";
    const size_t http_offset = ONION_SECTOR_NUM * SECTOR_SIZE + offsetof(OnionSector, szURLs);
    bool has_http = check_pattern(fp, http_offset, http_pattern, sizeof(http_pattern));
    if (has_http) printf("[+] Petya http address detected!\n");

    return has_bootloader || has_http;
}

bool decode(const BYTE *encoded, BYTE *key)
{
    int i, j;
    for (i = 0, j = 0; j < EXPANDED_KEY_LENGTH; i++, j+=2) {
        BYTE val = encoded[j];
        BYTE val2 = encoded[j+1];
        if (!val || !val2 || val - 'z' != val2 / 2) {
            return false;
        }
        key[i] = val - 'z';
    }
    key[i] = 0;
    return true;
}

int stage1(const OnionSector& os)
{
    char outbuf[PLAIN_KEY_LENGTH + 1];
    if (!decode(os.key, (BYTE*)outbuf)) {
        return -1;
    }
    if (strlen(outbuf) != 16) {
        return -2;
    }
    printf ("Key: %s\n", outbuf);
    return 0;
}

bool fetch_veribuf(FILE *fp, ByteBuff& verifyBuff, size_t size)
{
    verifyBuff.resize(size);
    fseek(fp, CHECK_BUFFER_SECTOR_NUM * SECTOR_SIZE, SEEK_SET);

    const size_t read = fread(&verifyBuff[0], size, 1, fp);
    return read == 1;
}

int stage2(const ByteBuff& veribuf, const OnionSector& os)
{
    {
        printf("\nverification data:\n");
        Base64encode(out_buf, reinterpret_cast<const char*>(&veribuf[0]), SECTOR_SIZE);
        printf("%s\n", out_buf);
    }
    {
        printf("\nnonce:\n");
        Base64encode(out_buf, reinterpret_cast<const char*>(os.iv), IV_LEN);
        printf("%s\n", out_buf);
    }
}

bool check_onion_sector_is_no_need_to_brute(const OnionSector& os)
{
    char tmp = '\0';
    switch (os.eEncrypted)
    {
    case OnionSector::ST_NotEncrypted:
        // try to restore original key from onion sector
        if (stage1(os) == 0) {
            printf("[OK] Stage 1 key recovered!\n");
            return true;
        }
        break;

    case OnionSector::ST_Encrypted:
        return false;

    case OnionSector::ST_Decrypted:
        printf("Looks like your drive is decrypted. Would do you like to find the key anyway? <Y>/<n>:");
        scanf("%c", &tmp);
        if (tmp == '\r' || tmp == '\n' || tmp == 'y' || tmp == 'Y')
            break;
        return true;
    default:
        printf("[-] Invalid Petya state, you have the newest version, possibly\n");
        break;
    }
    return false;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Supply the disk dump as a parameter!\n");
        return -1;
    }
    char* filename = argv[1];
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("Cannot open file %s\n", filename);
        return -1;
    }

    OnionSector os;
    fseek(fp, ONION_SECTOR_NUM * SECTOR_SIZE, SEEK_SET);
    size_t read = fread(&os, sizeof(OnionSector), 1, fp);
    if (read != 1) {
        printf("[-] Unable to read OnionSector\n");
        return -1;
    }

    if (is_infected(fp)) {
        printf("[+] Petya FOUND on the disk!\n");
    } else {
        printf("[-] Petya not found on the disk!\n");
        return -1;
    }
    printf("---\n");

    if (check_onion_sector_is_no_need_to_brute(os))
    {
        fclose(fp);
        return 0;
    }
    ByteBuff verifyBuff(SECTOR_SIZE, 0);
    fetch_veribuf(fp, verifyBuff, SECTOR_SIZE);
    fclose(fp);

    char key[PLAIN_KEY_LENGTH + 1] = {};
    printf("[+] Trying to decrypt... Please be patient...\n");

    if (!decrypt(os.iv, verifyBuff, key, PLAIN_KEY_LENGTH))
    {
        printf("[-] decrypt() failed\n");

        // printf("Invalid Stage1 key! Probably the key has been already erased!\n");
        printf("Try to recover from Stage2 by third-party decoder!\n");
        printf("Paste the data you got below on one of the following sites:\n");
        printf("+ https://petya-pay-no-ransom.herokuapp.com/\n");
        printf("+ https://petya-pay-no-ransom-mirror1.herokuapp.com/\n");
        stage2(verifyBuff, os);
        return 0;
    }

    return 0;
}

