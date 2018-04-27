#include "stealth.h"

#include "./random.h"
#include "./hash/hash.h"
#include "../utils/utils.h"


/* Hashes the key combined with the variable-encoded output_index
 *  key is either rA or Ra in the context of cryptonote keys
 */
void derivation_to_scalar(ec_scalar out, ec_point key, size_t output_index) {
    int ind_size = (sizeof(size_t) * 8 + 6) / 7;
    char toHash[32+ind_size];
    memcpy(toHash,key,32);
    size_t size;
    size = write_varint(toHash+32, output_index);
    hash_to_scalar(toHash, 32+size, out);
} 

/* Constructs a one-time public key for destination address (A,B)
 * 
 *  if rand is true, then we are not passing the r to the function
 *  if rand is false, we are using the r value already in addr->r
 * 
 *  sub is true if we are sending to a subaddress
 * 
 *  1. Choose a random r in [1, l - 1]
 *  2. Compute the one time public key: P = H(rA || n)G + B
 *  3. Calculate R = rG, which the receiver uses to recover the corresponding private keys
 */ 
void generateStealth(public_key A, public_key B, stealth_address* addr, bool rand, size_t output_index, bool sub) {
    ec_scalar temp_hash;
    ec_point rA;
    
    if (rand) {
        random_scalar(addr->r);                     //random r
    }
    scalarMult8(rA, addr->r, A);      
    derivation_to_scalar(temp_hash,rA,output_index);       //H(rA || n) 
    addKeys_multBase(addr->pub, temp_hash, B);  //P = H(rA)G + B
    if (sub) {
        scalarMult(addr->R,addr->r,B);              //R = rB (sD in MRL)
    } else {
        scalarMultBase(addr->R, addr->r);           //R = rG
    }
}

/* Determine if the public address is owned
 *  pub - The destination public key
 *  R - tx public key
 * (a,B)   Key pair used to determine ownership
 * 
 *  Calculate if the output of H(aR)G + B is equal to pub, if so return true and D is all 0
 *  If not, then set D = pub - H(aR)G and return false
 */
bool isStealthMine(public_key D, public_key pub, public_key R, secret_key a, public_key B, size_t output_index) {
    ec_scalar temp_hash;
    ec_point aR, P;

    scalarMult8(aR,a,R);                    //a*R
    derivation_to_scalar(temp_hash,aR,output_index);       //H(aR || n) 
    addKeys_multBase(P, temp_hash, B);      //P' = H(aR)G + B
    if (isByteArraysEqual(P, pub, 32)) {   //P ?= P'
        if (D != NULL) {
            memset(D,  0x00, 32);
        }
        return true;
    }
    subKeys_multBase(D, temp_hash, pub);    //D = P - H(aR)G
    return false;
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
void getStealthKey(secret_key priv, public_key R, secret_key a, secret_key b, size_t output_index) {
    ec_scalar temp_hash;
    ec_point aR;

    scalarMult8(aR,a,R);                    //a*R
    derivation_to_scalar(temp_hash,aR,output_index);   //H(rA || n)
    //don't use add_keys since we are just adding scalars, not points
    sc_add(priv,temp_hash,b);               //x = H(rA ||n) + b
}