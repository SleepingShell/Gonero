#ifndef UTILS_H
#define UTILS_H
#include <stdbool.h>

void printHex(unsigned char* s, int n);

void hexStrToBytes(char* s, unsigned char* dest, int n);

//Constant time byte array check, should maybe move to utils
bool isByteArraysEqual(char* s1, char* s2, int n);

size_t write_varint(char* dest, size_t i);

#endif