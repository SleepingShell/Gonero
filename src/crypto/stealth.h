#ifndef STLEATH_H
#define STEALTH_H
#include <stddef.h>

#include "keys.h"

typedef struct stealth_address {
    ec_scalar r;    //Private
    ec_point R;     //Transaction public key
    ec_point pub;   //One-time destination public key
} stealth_address;

void generateStealth(ec_point A, ec_scalar B, stealth_address* addr);
bool isStealthMine(ec_point pub, ec_point R, ec_scalar a, ec_point B);
void getStealthKey(ec_point* priv, ec_point R, ec_scalar a, ec_scalar b);

#endif