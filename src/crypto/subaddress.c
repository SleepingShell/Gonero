#include "subaddress.h"
#include "./hash/hash.h"

subaddress_index generate_subaddress_index(uint32_t major, uint32_t minor) {
    subaddress_index idx;
    idx.major = major;
    idx.minor = minor;
    return idx;
}

/* Generate the m value:
 *  m = H(prefix || a || major_i || minor_i)
 */
void subaddress_getm(ec_scalar m, secret_key a, subaddress_index index) {
    char prefix[] = "SubAddr";
    int data_size = sizeof(prefix) + sizeof(secret_key) + sizeof(subaddress_index);
    char data[data_size];
    memcpy(data, prefix, sizeof(prefix));
    memcpy(data+sizeof(prefix), a, sizeof(secret_key));
    memcpy(data+sizeof(prefix)+sizeof(secret_key), &index, sizeof(subaddress_index));
    hash_to_scalar(data, data_size, m);
}

/* Generate the public spend key, D, of a subaddress
 *  D = B + M
 */
void subaddress_get_public_spend(public_key D, secret_key a, public_key B, subaddress_index index) {
    ec_scalar m, M;
    subaddress_getm(m, a, index);   //m = H(a || i)
    scalarMultBase(M, m);           //M = m*G
    addKeys(D, B, M);               //D = M + B
}

/* Sub-addresses are addresses that have different public view and spend keys,
 * but can still be redeemed/scanned with the user's single private view/spend key
 * Generation:
 *  m = H(a || i)
 *  M = m*G
 *  D = B + M
 *  C = a*D
 */
void generate_subaddress(public_key D, public_key C, public_key B, secret_key a, subaddress_index index) {
    subaddress_get_public_spend(D,a,B,index);
    scalarMult(C, a, D);            //C = a*D
}

/* Retrieving the private key to stealth output is slightly different for subaddresses.
 * However, it only requires an addition to a normal stealth output. Therefore, call
 * getStealthKey() BEFORE calling this, and pass output as pre
 * 
 *  pre = H(aR) + b
 *  sec = pre + m = pre + H(a || i)
 *  sec = H(aR) + b + H(a || i)
 */
void subaddress_get_stealth_secret(secret_key sec, ec_scalar pre, secret_key a, subaddress_index index) {
    ec_scalar m;
    subaddress_getm(m,a,index);
    sc_add(sec, pre, m);
}