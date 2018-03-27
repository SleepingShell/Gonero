#include <stddef.h>
#include <stdio.h>

#include "utils.h"

void printHex(unsigned char* s, int n) {
    printf("0x");
    for (int i = 0; i < n; i++) {
        printf("%02x", s[i]);
    }
    printf("\n");
}

//Constant time byte array check
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

//Courtesy of The Monero project and The Cryptonote developers
//https://cryptonote.org/cns/cns003.txt
size_t write_varint(char* dest, size_t i) {
    /* Make sure that there is one after this */
    size_t size = 0;    //Number of bytes the varint takes
    while (i >= 0x80) {
      *dest = ((char)i & 0x7f) | 0x80; 
      ++dest;
      i >>= 7;			/* I should be in multiples of 7, this should just get the next part */
      size++;
    }
    /* writes the last one to dest */
    *dest = i;
    dest++;			/* Seems kinda pointless... */
    size ++;
    return size;
}