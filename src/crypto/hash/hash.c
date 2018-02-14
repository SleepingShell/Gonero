#include "hash.h"

//#include "keccak.h"
#include "../random.h"
#include "../crypto_math/crypto-ops.h"

void random_scalar(ec_scalar dest) {
    unsigned char temp[64];
    gen_random_bytes(32, temp);
    sc_reduce(temp);
    memcpy(dest, temp, 32);
}

//Only the first 32 bytes are used from the 200-byte output
void cn_fast_hash(void* data, size_t size, char* hash) {
    uint8_t temp[200];
    keccak1600(data, size, temp);
    memcpy(hash, temp, 32);
}

void hash_to_ec(void* in, size_t size, ge_p3* out) {
    char temp[32];
    ge_p2 t1;
    ge_p1p1 t2;
    cn_fast_hash(in, size, temp);           //Get the hash
    ge_fromfe_frombytes_vartime(&t1, temp);
    ge_mul8(&t2, &t1);                      //Multiply by 8 avoid small order sub-order issues
    ge_p1p1_to_p3(out, &t2);
   
}

void hash_to_ec_point(void* in, size_t size, ec_point out) {
    ge_p3 temp;
    hash_to_ec(in, size, &temp);
    ge_p3_tobytes(out, &temp);
}

void hash_to_scalar(void* in, size_t size, ec_scalar out) {
    cn_fast_hash(in, size, out);
    sc_reduce32(out);
}

void generate_key_image(secret_key x, public_key pub, key_image image) {
    ge_p3 hash;
    ge_p2 res;
    hash_to_ec(pub, 32, &hash);
    ge_scalarmult(&res, x, &hash);
    ge_tobytes(image, &res);
}