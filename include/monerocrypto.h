#include <stddef.h>
#include <stdbool.h>

typedef unsigned char ec_point[32];
typedef unsigned char ec_scalar[32];
typedef ec_point secret_key;    //Although sk is technically a scalar, both are represented by 32-bytes
typedef ec_point public_key;
typedef ec_point key_image;

void generate_keys(public_key pub, secret_key sk);
bool secret_to_public(public_key pub, secret_key sk);
void hash_to_scalar(void* in, size_t size, ec_scalar out);