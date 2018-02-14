#include <stddef.h>

#include "keys.h"

typedef struct ring_sig {
    key_image I;
    ec_scalar c1;
    ec_scalar* s;   //Array of s
    int n;          //Ring size (and size of s)
} ring_sig;

typedef struct mlsag_sig {
    vector_key_image imageV;
    ec_scalar c1;
    ec_scalar** s;
    int n, m;       //n is the size of the ring with each member having a vector m big
} mlsag_sig;

//Maybe signatures should be programmed in go
void generatellw(const char* msg, size_t msg_size, const vector_public_key* pubs, const key_image image, const secret_key sec, size_t index, ring_sig* sig);
bool verifyllw(const char* msg, size_t msg_size, vector_public_key* pubs, ring_sig* sig);
void generateMLSAG(const char* prefix, const matrix_public_key* pubM, const vector_key_image* imageV, const vector_secret_key* secV, size_t index, mlsag_sig* sig);