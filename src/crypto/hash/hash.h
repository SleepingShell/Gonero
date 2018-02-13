#ifndef HASH_H
#define HASH_H

#include <stddef.h>

#include <stdint.h>
#include <string.h>

#include "../keys.h"
#include "../crypto_math/crypto-ops.h"

union hash_state {
    uint8_t b[200]; //byte array
    uint64_t w[25]; //word array
};

enum {
    HASH_SIZE = 32,
    HASH_DATA_AREA = 136
};

void random_scalar(ec_scalar* dest);

//Output to a ge_p3 group element
void hash_to_ec(void* in, size_t size, ge_p3* out);

//Outputs to a point (32 byte array)
void hash_to_ec_point(void* in, size_t size, ec_point* out);
void hash_to_scalar(void* in, size_t size, ec_scalar* out);
void cn_fast_hash(void* data, size_t size, char* hash);

void generate_key_image(secret_key* x, public_key* pub, key_image* image);


/*----------Keccak.h---------*/
// keccak.h
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>


#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

// compute a keccak hash (md) of given byte length from "in"
void keccak(const uint8_t *in, size_t inlen, uint8_t *md, int mdlen);

// update the state
void keccakf(uint64_t st[25], int norounds);

void keccak1600(const uint8_t *in, size_t inlen, uint8_t *md);

#endif