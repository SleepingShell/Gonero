package main

/*
#cgo LDFLAGS: -L ../lib -lmonerocrypto
#include "../include/monerocrypto.h"
*/
import (
	"C"
)
import (
	"fmt"
	"unsafe"
	//"./crypto"
)

/*
func testIt() {
	signature.testHash()
}*/

func main() {
	var sk C.secret_key
	var pk C.public_key

	C.generate_keys(&pk, &sk)
	fmt.Printf("%x\n", sk)

	var skb [32]byte
	copy(skb[:], (*(*[32]byte)(unsafe.Pointer(&sk)))[:32:32])
	fmt.Printf("%x\n", skb)
}
