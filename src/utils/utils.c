#include <stddef.h>

#include "utils.h"

void printHex(unsigned char* s, int n) {
    printf("0x");
    for (int i = 0; i < n; i++) {
        printf("%x", s[i]);
    }
    printf("\n");
}

//Constant time byte array check, should maybe move to utils
bool isByteArraysEqual(char* s1, char* s2, int n) {
    int result = 0;
    for (size_t i = 0; i < n; i++) {
        result |= (s1[i] ^ s2[i]);
    }

    return result == 0;
}

//Read n/2 bytes into dest from a string s n characters long
void hexStrToBytes(char* s, unsigned char* dest, int n) {
    char* pos = s;
    unsigned int t;
    for (size_t i = 0; i < n / 2; i++) {
        sscanf((s + 2*i), "%2x", &t);
        dest[i] = t;
    }
}