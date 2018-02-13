cmake_minimum_required(VERSION 3.0)

set (CMAKE_C_STANDARD 11)

project(Crypto_test)

add_executable(
    main 
    main.c
    ../../src/crypto/keys.h
    ../../src/crypto/keys.c
    ../../src/crypto/random.h
    ../../src/crypto/random.c
    ../../src/crypto/hash/hash.h
    ../../src/crypto/hash/hash.c
    ../../src/crypto/hash/keccak.c
    ../../src/crypto/signatures.h
    ../../src/crypto/signatures.c
    ../../src/crypto/crypto_math/crypto-ops-data.c
    ../../src/crypto/crypto_math/crypto-ops.h
    ../../src/crypto/crypto_math/crypto-ops.c
)

#cmake -DCMAKE_BUILD_TYPE=Debug .
#^Run that command to enable -g 