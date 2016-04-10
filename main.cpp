// Petya recovery help
// by: hasherezade
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "base64.h"

#define SECTOR 0x200

char out_buf[0x400];

bool decode(char *encoded, char *key) 
{
    int i, j;
    for (i = 0, j = 0; j < 32; i++, j+=2) {
        char val = encoded[j];
        char val2 = encoded[j+1];
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
    if (decode(encoded_key, outbuf) == false) {
        printf("Cannot find the Stage1 key!\n");
        return -1;
    }

    if (strlen(outbuf) != 16) {
        printf("Invalid Stage1 key length!\n");
        return -2;
    }
    printf ("Key: %s\n", outbuf);
    return 0;
}

void fetch_data(FILE *fp, const size_t offset, const size_t in_size)
{
    char in_buf[in_size];
    memset(in_buf, 0, in_size);
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
    
    if (stage1(fp) == 0) {
        printf("[OK] Stage 1 key recovered!");
        fclose(fp);
        return 0;
    }
    printf("Try to recover from Stage2 by third-party decoder!\n");
    printf("Paste this data to: https://petya-pay-no-ransom.herokuapp.com/\n");
    stage2(fp);
    fclose(fp);
}

