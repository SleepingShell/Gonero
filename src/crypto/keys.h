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
    //vector_public_key* pub_vectors;
    public_key** pub_vectors;
    int ring_size;      //n
    int vector_size;   //Number of keys per ring (m)
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

/*Generate a new secret and public key pair, calls random_scalar
 */
void generate_keys(public_key pub, secret_key sk);

/*Get the corresponding public key to the given secret key
 * Returns false if sk is not valid
 */ 
bool secret_to_public(public_key pub, secret_key sk);
bool check_key(const public_key pub);

    /* ======================================== */
    /*          Key and point math              */
    /* ======================================== */

//out = aG
void scalarMultBase(ec_scalar out, ec_scalar a);

//TODO: Handle errors on ge_frombytes_vartime
//out = A + B
void addKeys(ec_point out, ec_point A, ec_point B);

//out = A - B
void subKeys(ec_point out, ec_point A, ec_point B);

//out = aG + B
void addKeys_multBase(ec_point out, ec_scalar a, ec_point B);

//out = aG + bB
void addKeys_double_multBase(ec_point out, ec_scalar a, ec_scalar b, ec_point B);

//out = B - aG
void subKeys_multBase(ec_point out, ec_scalar a, ec_point B);

//out = 8*in
void mul8(ec_point out, ec_point in);

//out = a*B
void scalarMult(ec_point out, ec_scalar a, ec_point B);

//out = 8*a*B
void scalarMult8(ec_point out, ec_scalar a, ec_point B);

#endif