#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "../../src/crypto/keys.h"
#include "../../src/crypto/hash/hash.h"
#include "../../src/crypto/signatures.h"

//Longest line in tests.txt is 49569
#define MAX_LINE_LENGTH 49800

/*
void printHex(unsigned char* s, int n) {
    printf("0x");
    for (int i = 0; i < n; i++) {
        printf("%x", s[i]);
    }
    printf("\n");
}
*/

//Read n/2 bytes into dest from a string s n characters long
void hexStrToBytes(char* s, unsigned char* dest, int n) {
    char* pos = s;
    unsigned int t;
    for (size_t i = 0; i < n / 2; i++) {
        sscanf((s + 2*i), "%2x", &t);
        dest[i] = t;
    }
}

void test_ring_sig() {
    
    int n = 5;
    int index = 2;
    public_key pubs[n];
    secret_key secs[n];
    for (size_t i = 0; i < n; i++) {
        generate_keys(pubs[i], secs[i]);
    }

    vector_public_key pubV;
    pubV.n = n;
    pubV.pub_keys = pubs;

    char msg[] = {0x01, 0x02};
    size_t msg_size = 2;

    key_image image;
    generate_key_image(secs[index], pubs[index], image);

    ring_sig sig;
    sig.s = malloc(sizeof(ec_scalar)*n);
    generatellw(msg,msg_size,&pubV,image,secs[index],index,&sig);

    printHex(sig.c1, 32);

    bool res = verifyllw(msg,msg_size,&pubV,&sig);
    printf("Verification result: %s\n", res ? "true" : "false");
    
    /*
    unsigned char msg[32];
    hexStrToBytes("89226689e486049662075f55d46361d821c5ede1fc172581458207aeb3d7374b", msg, 64);
    key_image image;
    hexStrToBytes("4048d63774cf0e3d73059b76c1160f5b36fae2add758c0b5d0a76eccf459081b", image, 64);
    int n = 2;
    vector_public_key pubV;
    public_key pubs[n];
    hexStrToBytes("68943d3665e40eaa5d8ce9a3279e70e9d00afa0cea15d6671e024efcdad2900c", pubs[0], 64);
    hexStrToBytes("fb89cf7108eb3b68243e732e820d716e11a0baa0def8d2d837ab998a9bd642c0", pubs[1], 64);
    pubV.n = n;
    pubV.pub_keys = pubs;
    secret_key sec;
    int index = 1;
    hexStrToBytes("f75b48b628a7f3fd1dce1055f7c0b81c36454e012dc7ead8d5528c11cd52990d", sec, 64);
    ring_sig sig;
    sig.s = malloc(sizeof(ec_scalar)*n);
    generatellw(msg, 32, &pubV, image, sec, index, &sig);
    printHex(sig.c1, 32);
    */
}

void test_mlsag() {
    int ring_size = 500;
    int vector_size = 10;
    int index = 50;

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
    printHex(sig.c1, 32);
    bool res = verifyMLSAG(msg, &pubM, &sig);
    printf("Verification result: %s\n", res ? "true" : "false");
}

void main() {

    FILE* fd = fopen("tests.txt", "r");
    if (!fd) {
        err(1, "Error opening tests.txt");
    }

    //char buffer[MAX_LINE_LENGTH];
    char* buffer = malloc(MAX_LINE_LENGTH);
    if (buffer == NULL) {
        err(1, "Error allocating buffer");
    }
    char* cur;
    int lineNo = 0;

    
    while (fgets(buffer, MAX_LINE_LENGTH, fd)) {
        lineNo++;
        cur = strtok(buffer, " ");
        
        if (strcmp("secret_key_to_public_key", cur) == 0) {
            char secString[65];
            char resultString[6];
            char pubString[65];

            secret_key sk;
            public_key pub, pub_expected;
            bool res, res_expected;
            cur = strtok(NULL, " ");
            strcpy(secString, cur);
            hexStrToBytes(secString, sk, 64);

            cur = strtok(NULL, " ");
            strcpy(resultString, cur);
            resultString[5] = '\0';
            if (!(strcmp(resultString, "false") == 0)) {
                cur = strtok(NULL, " ");
                strcpy(pubString, cur);
                hexStrToBytes(pubString, pub_expected, 64);
                res_expected = true;
            } else {
                res_expected = false;
            }

            res = secret_to_public(pub, sk);
            
            if (res == res_expected && isByteArraysEqual(pub,pub_expected,32)) {
                //printf("%d passed\n", lineNo);
            } else {
                printf("%d Failed\n", lineNo);
            }
            
        } else if (strcmp("hash_to_ec", cur) == 0) {
            char inString[65];
            char expected[65];

            public_key in;
            //ec_point out, out_expected;
            ge_p3 out, out_expected;
            char out_expectedBytes[32], outBytes[32];

            cur = strtok(NULL, " ");
            strcpy(inString, cur);
            hexStrToBytes(inString, in, 64);

            cur = strtok(NULL, " ");
            strcpy(expected, cur);
            hexStrToBytes(expected, out_expectedBytes, 64);
            //ge_frombytes_vartime(&out_expected, out_expectedBytes);

            hash_to_ec(in, 32, &out);

            ge_p3_tobytes(outBytes, &out);

            if ( !isByteArraysEqual(outBytes,out_expectedBytes,32) ) {
                printf("%d Failed\n", lineNo);
            }

        } else if (strcmp("generate_key_image", cur) == 0) {
            char pubString[65];
            char secString[65];
            char expectedString[65];

            public_key pub;
            secret_key sec;
            key_image expected;

            cur = strtok(NULL, " ");
            strcpy(pubString, cur);
            hexStrToBytes(pubString, pub, 64);

            cur = strtok(NULL, " ");
            strcpy(secString, cur);
            hexStrToBytes(secString, sec, 64);

            cur = strtok(NULL, " ");
            strcpy(expectedString, cur);
            hexStrToBytes(expectedString, expected, 64);

            key_image real;
            generate_key_image(sec, pub, real);

            if ( !isByteArraysEqual(real, expected, 32) ) {
                printf("%d Failed\n", lineNo);
            }
        }
    }

    printf("********Finished tests********\n");

    free(buffer);
    fclose(fd);

    test_ring_sig();
    test_mlsag();
}