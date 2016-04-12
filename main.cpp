// Petya recovery help
// by: hasherezade
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "base64.h"

#define SECTOR 0x200

typedef unsigned char BYTE;

char out_buf[0x400];

bool check_pattern(FILE *fp, size_t offset, const char *cmp_buf, size_t cmp_size)
{
    //cmp_size = (cmp_size > sizeof(out_buf)) ? sizeof(out_buf) : cmp_size;

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
    const size_t http_offset = 54 * SECTOR + 0x29;
    bool has_http = check_pattern(fp, http_offset, http_pattern, sizeof(http_pattern));
    if (has_http) printf("[+] Petya http address detected!\n");

    return has_bootloader || has_http;
}

bool decode(BYTE *encoded, BYTE *key) 
{
    int i, j;
    for (i = 0, j = 0; j < 32; i++, j+=2) {
        BYTE val = encoded[j];
        BYTE val2 = encoded[j+1];
        if (val == 0) break;
        if (val - 'z' != val2 / 2) {
            return false;
        }
        key[i] = val - 'z';
    }
    key[i] = 0;
    return true;
}

int stage1(FILE *fp)
{
    size_t offset = 54 * SECTOR + 1;
    fseek(fp, offset, SEEK_SET);

    char encoded_key[33];
    fread(encoded_key, 1, 32, fp);

    char outbuf[32];
    if (decode((BYTE*)encoded_key, (BYTE*)outbuf) == false) {
        printf("Cannot find the Stage1 key!\n");
        return -1;
    }
    if (strlen(outbuf) != 16) {
        printf("Invalid Stage1 key! Probably the key has been already ereased!\n");
        return -2;
    }
    printf ("Key: %s\n", outbuf);
    return 0;
}

void fetch_data(FILE *fp, const size_t offset, const size_t in_size)
{
    char in_buf[in_size];
    fseek(fp, offset, SEEK_SET);
    size_t read = fread(in_buf, 1, in_size, fp);
    if (read != in_size) {
        printf("Error, read = %d\n", read);
        return;
    }
    Base64encode(out_buf, in_buf, in_size);
    printf("%s\n", out_buf);
}

void fetch_veribuf(FILE *fp)
{
    size_t offset = 55 * SECTOR;
    printf("\nverification data:\n");
    fetch_data(fp, offset, SECTOR);
}

void fetch_nonce(FILE *fp)
{
    size_t offset = 54 * SECTOR + 0x21;
    printf("\nnonce:\n");
    fetch_data(fp, offset, 8);
}

int stage2(FILE *fp)
{
    fetch_veribuf(fp);
    fetch_nonce(fp);
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
        printf("Cannot open file\n");
        return -1;
    }

    if (is_infected(fp)) {
        printf("[+] Petya FOUND on the disk!\n");
    } else {
        printf("[-] Petya not found on the disk!\n");
    }
    printf("---\n");

    if (stage1(fp) == 0) {
        printf("[OK] Stage 1 key recovered!\n");
        fclose(fp);
        return 0;
    }
    printf("Try to recover from Stage2 by third-party decoder!\n");
    printf("Paste this data to: https://petya-pay-no-ransom.herokuapp.com/\n");
    stage2(fp);
    fclose(fp);
    return 0;
}

