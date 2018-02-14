#include <stdbool.h>

#include "./crypto_math/crypto-ops.h"

#include "keys.h"
#include "random.h"

/* generate a random 32-byte (256-bit) integer and copy it to res 
  * Will keep this not_thread_safe
 */
static inline void random_scalar_not_thread_safe(ec_scalar res) {
    unsigned char tmp[64];
    //random_bytes_system(64, tmp);
    gen_random_bytes(64, tmp);
    sc_reduce(tmp);
    memcpy(res, tmp, 32);
  }

static inline void random_scalar(ec_scalar res) {
    random_scalar_not_thread_safe(res);
}

void generate_keys(public_key pub, secret_key sk) {
    random_scalar(sk);
    sc_reduce(sk);
    secret_to_public(pub,sk);
}

bool secret_to_public(public_key pub, secret_key sk) {
    ge_p3 point;
    if (sc_check(sk) != 0) { return false; }
    ge_scalarmult_base(&point, sk);
    ge_p3_tobytes(pub, &point);
    return true;
}