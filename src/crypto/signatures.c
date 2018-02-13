#include "signatures.h"
#include "./hash/hash.h"
#include "./crypto_math/crypto-ops.h"

void printHex(unsigned char* s, int n) {
    printf("0x");
    for (int i = 0; i < n; i++) {
        printf("%x", s[i]);
    }
    printf("\n");
}

//Constant time byte array check, should maybe move to utils
bool isByteArraysEqual(char* s1, char* s2, int n) {
    int result = 0;
    for (size_t i = 0; i < n; i++) {
        result |= (s1[i] ^ s2[i]);
    }

    return result == 0;
}

/* Calculate the L and R values and put them in their byte arrays
 * Used in LWW and MLSAG
 */
void calc_LR(char* L_curBytes, char* R_curBytes, ec_scalar* c_prev, ec_scalar s, public_key pub, ge_dsmp image_pre) {
    ge_p3 pub_cur;
    ge_p3 pubhash_cur;
    ge_dsmp pubhash_pre;
    ge_p3 L_cur;
    ge_p3 R_cur;
    ge_p2 temp_p2;
    ge_frombytes_vartime(&pub_cur, pub);
    ge_double_scalarmult_base_vartime(&temp_p2, c_prev, &pub_cur, s);
    ge_tobytes(L_curBytes, &temp_p2);

    hash_to_ec(pub, 32, &pubhash_cur);
    ge_dsm_precomp(pubhash_pre, &pubhash_cur);
    ge_double_scalarmult_precomp_vartime2_p3(&R_cur,s,pubhash_pre,c_prev,image_pre);
    ge_p3_tobytes(R_curBytes, &R_cur);
}

/*----------Calculate values for secret index----------*/
void calc_LR_secret(char* L_curBytes, char* R_curBytes, ec_scalar s, public_key pub) {
    ge_p3 pubhash_cur;
    ge_p3 L_cur, R_cur;
    ge_scalarmult_base(&L_cur, s);
    ge_p3_tobytes(L_curBytes, &L_cur);
    hash_to_ec(pub, 32, &pubhash_cur);
    ge_scalarmult_p3(&R_cur, s, &pubhash_cur);
    ge_p3_tobytes(R_curBytes, &R_cur);
    /*--------------------------*/

}

void generatellw(const char* msg, size_t msg_size, const vector_public_key* pubs, const key_image image, const secret_key sec, size_t index, ring_sig* sig) {
    int n = pubs->n;
    public_key* pub_keys = pubs->pub_keys;

    ec_scalar s[n];
    ec_scalar c;

    int toHash_size = msg_size+32+32;
    char toHash[toHash_size];           //This stores the stuff we hash to get c
    memcpy(toHash, msg, msg_size);

    ge_p3 key_image_p3;
    ge_frombytes_vartime(&key_image_p3, image);
    ge_dsmp image_pre;
    ge_dsm_precomp(image_pre, &key_image_p3);

    char L_curBytes[32];
    char R_curBytes[32];

    int i = index;    
    random_scalar(&s[i]);
    calc_LR_secret(L_curBytes, R_curBytes, s[i], pub_keys[i]);
    memcpy(toHash+(toHash_size-64), L_curBytes, 32);
    memcpy(toHash+(toHash_size-32), R_curBytes, 32);
    hash_to_scalar(toHash, toHash_size, c);

    i = (i + 1) % n;
    if (i == 0) {
        memcpy(sig->c1, c, 32);
    }
    printf("c_%d: ", i);
    printHex(c, 32);

    while (i != index) {
        random_scalar(s[i]);

        calc_LR(L_curBytes, R_curBytes, &c, s[i], pub_keys[i], image_pre);
        memcpy(toHash+(toHash_size-64), L_curBytes, 32);
        memcpy(toHash+(toHash_size-32), R_curBytes, 32);
        hash_to_scalar(toHash, toHash_size, c);

        i = (i + 1) % n;
        if (i == 0) {
            memcpy(&sig->c1, &c, 32);
        }
        printf("c_%d: ", i);
        printHex(c, 32);
    }

    sc_mulsub(s[index],c,sec,s[index]);

    for (i = 0; i < n; i++) {
        memcpy(sig->s[i], s[i], 32);
        memcpy(sig->I, image, 32);
    }

    printf("s[0]: ");
    printHex(s[0], 32);
    printf("pub[0]: ");
    printHex(pub_keys[0],32);
    printf("key_image: ");
    printHex(image, 32);

    printf("-----end generatellw2------\n");
}

bool verifyllw(const char* msg, size_t msg_size, vector_public_key* pubs, ring_sig* sig) {
    printf("----Verifying-----\n");
    int n = pubs->n;
    public_key* pub_keys = pubs->pub_keys;

    key_image image;
    memcpy(&image,sig->I,32);
    ec_scalar c_cur;
    memcpy(&c_cur,&sig->c1,32);
    ec_scalar* s = sig->s;

    int toHash_size = msg_size+32+32;
    char toHash[toHash_size];           //This stores the stuff we hash to get c
    memcpy(toHash, msg, msg_size);

    ge_p3 key_image_p3;
    ge_frombytes_vartime(&key_image_p3, image);
    ge_dsmp image_pre;
    ge_dsm_precomp(image_pre, &key_image_p3);

    char L_curBytes[32];
    char R_curBytes[32];

    printf("c_0: ");
    printHex(c_cur,32);

    int i = 0;
    while (i < n) {
        //calc_c_value(&c_cur,s[i],pub_keys[i],image_pre,toHash,toHash_size);
        calc_LR(L_curBytes, R_curBytes, &c_cur, s[i], pub_keys[i], image_pre);
        memcpy(toHash+(toHash_size-64), L_curBytes, 32);
        memcpy(toHash+(toHash_size-32), R_curBytes, 32);
        hash_to_scalar(toHash, toHash_size, c_cur);
        i = (i + 1);
        printf("c_%d: ", i);
        printHex(c_cur, 32);
    }

    return isByteArraysEqual(sig->c1, c_cur,32);
}

/*
 * Calculates the hash of the message given L and R MLSAG vectors
 * L and R are vectors of size m
 */
void calc_c_hashV(char* c, char** L, char** R, int m, char* toHash, int prefix_size) {
    //int m = L.n;
    for (size_t i = 0; i < m; i++) {
        memcpy(toHash+prefix_size+(32*(2*i)), L[i], 32);
        memcpy(toHash+prefix_size+(32*((2*i)+1)), R[i], 32);
    }
    hash_to_scalar(toHash, prefix_size+(32*(m*2)), c);
}