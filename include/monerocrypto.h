typedef unsigned char ec_point[32];
typedef unsigned char ec_scalar[32];
typedef ec_point secret_key;    //Although sk is technically a scalar, both are represented by 32-bytes
typedef ec_point public_key;
typedef ec_point key_image;

void generate_keys(public_key* pub, secret_key* sk);