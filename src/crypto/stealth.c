#include "stealth.h"

#include "./random.h"
#include "./hash/hash.h"
#include "../utils/utils.h"

/* Constructs a one-time public key for destination address (A,B)
 * 
 *  1. Choose a random r in [1, l - 1]  (Only 32-bit in current implementation)
 *  2. Compute the one time public key: P = H(rA)G + B
 *  3. Calculate R = rG, which the receiver uses to recover the corresponding private keys
 */ 
void generateStealth(ec_point A, ec_scalar B, stealth_address* addr) {
    ec_scalar temp_hash;
    ec_point rA;
    
    random_scalar(addr->r);                     //random r
    sc_mul(rA, addr->r, A);
    hash_to_scalar(rA,32,temp_hash);            //H(rA)
    addKeys_multBase(addr->pub, temp_hash, B);  //P = H(rA)G + B
    scalarMultBase(addr->R, addr->r);           //R = rG
}

/* Determine if the public address is owned
 *  pub - The destination public key
 *  R - tx public key
 * (a,B)   Key pair used to determine ownership
 * 
 * 1. Calculate if the output of H(aR)G + B is equal to pub
 */
bool isStealthMine(ec_point pub, ec_point R, ec_scalar a, ec_point B) {
    ec_scalar temp_hash;
    ec_point aR, P;

    sc_mul(aR, a, R);                       //a*R
    hash_to_scalar(aR, 32, temp_hash);      //H(aR)
    addKeys_multBase(P, temp_hash, B);      //P' = H(aR)G + B
    return isByteArraysEqual(P, pub, 32);   //P ?= P'
}

/* Get the one-time private key from a stealth address
 *  priv - pointer to where the private key will be stored
 *  R - transaction public key
 *  (a,b) - User's long-term private key pair
 * 
 * x = H(aR) + b
 * 
 * ASSUMES CALLER HAS ALREADY CHECKED IF TX BELONGS TO (a,b)
 */
void getStealthKey(ec_point priv, ec_point R, ec_scalar a, ec_scalar b) {
    ec_scalar temp_hash;
    ec_point aR;

    sc_mul(aR, a, R);   //Perhaps this should be stored since it is called in 2 functions
    hash_to_scalar(aR, 32, temp_hash);
    addKeys(priv, temp_hash, b);    //x = H(aR) + b
}