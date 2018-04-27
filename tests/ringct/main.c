#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <stdint.h>

#include "../../src/crypto/keys.h"
#include "../../src/crypto/hash/hash.h"
#include "../../src/crypto/signatures.h"
#include "../../src/crypto/rangeproofs.h"
#include "../../src/utils/utils.h"

//Longest line in tests.txt is 49569
#define MAX_LINE_LENGTH 49800

void test_mlsag() {
    printf("Testing mlsag...\n");
    int ring_size = 20;
    int vector_size = 10;
    int index = 5;

    matrix_public_key pubM;
    pubM.vector_size = vector_size;
    pubM.ring_size = ring_size;

    public_key** pubVs;
    pubVs = malloc(ring_size*sizeof(public_key*));
    for (size_t i=0; i < ring_size; i++) {
        pubVs[i] = malloc(vector_size*sizeof(public_key));
    }
    pubM.pub_vectors = pubVs;

    vector_secret_key secV;
    secV.n = vector_size;
    secV.sec_keys = malloc(sizeof(secret_key)*vector_size);

    vector_key_image imageV;
    imageV.n = vector_size;
    imageV.images = malloc(sizeof(key_image)*vector_size);

    secret_key temp;
    //For each vector
    for (size_t i = 0; i < ring_size; i++ ) {
        //Each member in vector
        for (size_t j = 0; j < vector_size; j++) {
            if (i == index) {
                generate_keys(pubVs[i][j], secV.sec_keys[j]);
                generate_key_image(secV.sec_keys[j],pubVs[i][j],imageV.images[j]);
            } else {
                generate_keys(pubVs[i][j],temp);
            }

        }
    }

    char msg[32];
    for (size_t i = 0; i < 32; i++) {
        msg[i] = 0x01;
    }

    mlsag_sig sig;
    //sig.s = malloc(sizeof(vector_ec_scalar*)*ring_size);
    sig.s = malloc(ring_size*sizeof(ec_scalar*));
    for (size_t i = 0; i < ring_size; i++) {
        //sig.s[i].scalars = (vector_ec_scalar*)malloc(sizeof(ec_scalar)*vector_size);
        //sig.s[i].n = vector_size;
        sig.s[i] = malloc(vector_size*sizeof(ec_scalar));
    }

    sig.imageV.images = malloc(sizeof(key_image)*vector_size);
    for (size_t i = 0; i < vector_size; i++) {
        memcpy(sig.imageV.images[i], imageV.images[i],32);
    }

    generateMLSAG(msg,&pubM,&imageV,&secV,index,&sig);
    bool res = verifyMLSAG(msg, &pubM, &sig);
    printf("Verification result: %s\n", res ? "true" : "false");
}

uint64_t h2d(ec_scalar t) {
    uint64_t vali = 0;
    int j = 0;
    for (j = 7; j >= 0; j--) {
        vali = (uint64_t)(vali*256*(unsigned char)t[j]);
    }
    return vali;
}


void test_rangeproof() {
    printf("Testing rangeproof...\n");
    ec_scalar C, mask;
    uint64_t amount = 5;
    range_proof proof;
    proveRange(C,mask,amount,&proof);
    //printHex(C, 32);
    //printHex(mask, 32);

    bool res = verifyRange(C, &proof);
    printf("Verification result: %s\n", res ? "true" : "false");

    printf("=====================\n");

    int N = 64;
    ec_scalar temp;
    key64 xv;
    key64 P1v;
    key64 P2v;
    bits indi;
    int j = 0;

    for (j = 0; j < N; j++) {
        random_scalar(temp);
        indi[j] = (int)(h2d(temp) % 2);

        random_scalar(temp);
        memcpy(xv[j],temp,32);

        if( (int)indi[j] == 0) {
            scalarMultBase(P1v[j], xv[j]);
        } else {
            addKeys_multBase(P1v[j], xv[j], H2[j]);
        }
        subKeys(P2v[j], P1v[j], H2[j]);
    }

    borromean_sig bsig;

    generateBorromean(xv,P1v,P2v,indi,&bsig);
    
    res = verifyBorromean(P1v,P2v,&bsig);
    printf("Verification result: %s\n", res ? "true" : "false");
}

void ctskpkGen(uint64_t amount) {
    
}

void test_rangeproof2() {

}

int main() {
    test_mlsag();
    test_rangeproof();

    return 0;
}