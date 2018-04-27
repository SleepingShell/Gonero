#ifndef STLEATH_H
#define STEALTH_H
#include <stddef.h>

#include "keys.h"

//R should be put into a separate structure than the output-specific info (pub)
typedef struct stealth_address {
    ec_scalar r;    //Private
    ec_point R;     //Transaction public key
    ec_point pub;   //One-time destination public key
} stealth_address;

void generateStealth(public_key A, public_key B, stealth_address* addr, bool rand, size_t output_index, bool sub);
bool isStealthMine(public_key D, public_key pub, public_key R, secret_key a, public_key B, size_t output_index);
void getStealthKey(secret_key priv, public_key R, secret_key a, secret_key b, size_t output_index);

#endif