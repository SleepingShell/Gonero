#ifndef KEYS_H
#define KEYS_H

#include <stdbool.h>

/*These types do not need to be passed as a pointer. Passing ec_scalar
 * to a function (no *) will pass as char*
 */
typedef unsigned char ec_point[32];
typedef unsigned char ec_scalar[32];
typedef ec_scalar secret_key;    //Although sk is technically a scalar, both are represented by 32-bytes
typedef ec_point public_key;
typedef ec_point key_image;

typedef struct vector_public_key {
    public_key* pub_keys;
    unsigned int n;
} vector_public_key;

typedef struct matrix_public_key {
    vector_public_key* pub_vectors;
    int num_vectors;
    int num_keys;   //Number of keys per vector
} matrix_public_key;


typedef struct vector_ec_scalar {
    ec_scalar* scalars;
    int n;
} vector_ec_scalar;

//typedef vector_ec_scalar vector_secret_key;

typedef struct vector_secret_key {
    secret_key* sec_keys;
    int n;
} vector_secret_key;

typedef struct vector_key_image {
    key_image* images;
    int n;
} vector_key_image;


/***Functions***
 *  Callers are responsible for allocation and freeing of memory 
 */

//Generate a random scalar and create and assign public and secret key their respective information
void generate_keys(public_key pub, secret_key sk);

/*Get the corresponding public key to the given secret key
 * Returns false if sk is not valid
 */ 
bool secret_to_public(public_key pub, secret_key sk);
bool check_key(const public_key pub);

#endif