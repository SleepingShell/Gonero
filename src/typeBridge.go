package main

/*
#cgo LDFLAGS: -L ../lib -lmonerocrypto
#include "./crypto/keys.h"
*/
import "C"
import "unsafe"

//Key represents an ecc key, public or private (32 bytes)
type Key [32]byte

//Scalar represents an elliptic curve scalar (32 bytes)
type Scalar [32]byte

//Point represents an elliptic curve point (32 bytes)
type Point [32]byte

//CpublicKeyTogoKey returns a Key pointer that points to the
//C.public_key address in src.
func CpublicKeyTogoKey(src C.public_key) *Key {
	return (*Key)(unsafe.Pointer(&src))
}

//CscalarToByteSlice returns a []byte pointer that points to the
//C.ec_scalar address in src
func CscalarToByteSlice(src *C.ec_scalar) *[32]byte {
	return (*[32]byte)(unsafe.Pointer(src))
}

//CscalarToCuchar returns a C.uchar pointer that points to the
//C.ec_scalar address in src
func CscalarToCuchar(src *C.ec_scalar) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(src))
}

//CpointToCuchar returns a C.uchar pointer that points to the
//C.ec_point address in src
func CpointToCuchar(src *C.ec_point) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(src))
}

//CsecretKeyTouchar returns a C.uchar pointer that points to the
//C.secret_key address in src.
func CsecretKeyTouchar(src C.secret_key) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&src))
}

//GoKeyToCPublicKey returns a C.public_key pointer that points to the
//Key address in src.
func GoKeyToCPublicKey(src *Key) *C.public_key {
	return (*C.public_key)(unsafe.Pointer(src))
}

//GoKeyToCSecretKey returns a C.secret_key pointer that points to the
//Key address in src.
func GoKeyToCSecretKey(src *Key) *C.secret_key {
	return (*C.secret_key)(unsafe.Pointer(src))
}

//GoKeyToUcharPtr returns a C.uchar pointer (array of char) to the
//Key address in src
func GoKeyToUcharPtr(src *Key) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(src))
}

//GoScalarToUcharPtr returns a C.uchar pointer (array of char) to the
//Scalar address in src
func GoScalarToUcharPtr(src *Scalar) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(src))
}
