#ifndef SUBADDRESS_H
#define SUBADDRESS_H

#include <stdint.h>

#include "keys.h"

typedef struct subaddress_index {
    uint32_t major;
    uint32_t minor;
} subaddress_index;

subaddress_index generate_subaddress_index(uint32_t major, uint32_t minor);

/* Generate a sub-address given the secret view key a
 * MRL-0006
 */
void generate_subaddress(public_key D, public_key C, public_key B, secret_key a, subaddress_index index);

/* Get the m value, used in public key generation and secret-key retrieval
 */
void subaddress_getm(ec_scalar m, secret_key a, subaddress_index index);

void subaddress_get_public_spend(public_key D, secret_key a, public_key B, subaddress_index index);

/* Get the secret key to a one-time key destined for a subaddress.
 *      pre holds the value from getStealthKey()    H(aR) + b
 *  sec = pre + m
 */
void subaddress_get_stealth_secret(secret_key sec, ec_scalar pre, secret_key a, subaddress_index index);

#endif