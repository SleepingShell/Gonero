#include <stdbool.h>

#include "./crypto_math/crypto-ops.h"

#include "keys.h"
#include "random.h"

/* generate a random 32-byte (256-bit) integer and copy it to res 
  * Will keep this not_thread_safe
 */
static inline void random_scalar_not_thread_safe(ec_scalar res) {
    unsigned char tmp[64];
    gen_random_bytes(64, tmp);
    sc_reduce(tmp);
    memcpy(res, tmp, 32);
}

static inline void random_scalar(ec_scalar res) {
    random_scalar_not_thread_safe(res);
}

void generate_keys(public_key pub, secret_key sk) {
    random_scalar(sk);
    //sc_reduce(sk);              //I don't think this is needed...
    secret_to_public(pub,sk);
}

bool secret_to_public(public_key pub, secret_key sk) {
    ge_p3 point;
    if (sc_check(sk) != 0) { return false; }
    ge_scalarmult_base(&point, sk);
    ge_p3_tobytes(pub, &point);
    return true;
}

//out = aG
void scalarMultBase(ec_scalar out, ec_scalar a) {
    ge_p3 temp_p3;
    ge_scalarmult_base(&temp_p3, a);
    ge_p3_tobytes(out, &temp_p3);
}

//TODO: Handle errors on ge_frombytes_vartime
//out = A + B
void addKeys(ec_point out, ec_point A, ec_point B) {
    ge_p3 A3, B3;
    ge_cached Bcache;
    ge_p1p1 res;

    ge_frombytes_vartime(&A3, A);
    ge_frombytes_vartime(&B3, B);
    ge_p3_to_cached(&Bcache, &B3);
    ge_add(&res, &A3, &Bcache);
    ge_p1p1_to_p3(&A3, &res);
    ge_p3_tobytes(out, &A3);
}

//out = aG + B
void addKeys_multBase(ec_point out, ec_scalar a, ec_point B) {
    ec_scalar aG;
    scalarMultBase(aG, a);
    addKeys(out, aG, B);
}

//out = aG + bB
void addKeys_double_multBase(ec_point out, ec_scalar a, ec_scalar b, ec_point B) {
    //ec_scalar aG;
    //ec_scalar bB;
    //scalarMultBase(aG, a);
    ge_p3 B3;
    ge_p2 res;
    ge_frombytes_vartime(&B3, B);
    ge_double_scalarmult_base_vartime(&res,b,&B3,a);
    ge_tobytes(out, &res);
}