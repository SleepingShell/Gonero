cmake_minimum_required(VERSION 3.0)

set (CMAKE_C_STANDARD 11)

#DESCRIPTION "crypto used by Monero"
project(monerocrypto VERSION 0.1.0 LANGUAGES C)
include(GNUInstallDirs)

add_library(
    monerocrypto STATIC
    ../src/crypto/keys.h
    ../src/crypto/keys.c
    ../src/crypto/random.h
    ../src/crypto/random.c
    ../src/crypto/hash/hash.h
    ../src/crypto/hash/hash.c
    ../src/crypto/hash/keccak.c
    ../src/crypto/signatures.h
    ../src/crypto/signatures.c
    ../src/crypto/rangeproofs.h
    ../src/crypto/rangeproofs.c
    ../src/crypto/stealth.h
    ../src/crypto/stealth.c
    ../src/crypto/subaddress.h
    ../src/crypto/subaddress.c
    ../src/crypto/crypto_math/crypto-ops-data.c
    ../src/crypto/crypto_math/crypto-ops.h
    ../src/crypto/crypto_math/crypto-ops.c
    ../src/utils/utils.h
    ../src/utils/utils.c
)

set_target_properties(monerocrypto PROPERTIES 
    VERSION ${PROJECT_VERSION}
    PUBLIC_HEADER include/monerocrypto.h
)

install(TARGETS monerocrypto
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

file(COPY "${CMAKE_SOURCE_DIR}/libmonerocrypto.a" DESTINATION "../lib")