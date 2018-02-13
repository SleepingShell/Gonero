package main

/*
#cgo CFLAGS: -I ./hash
#include "./hash/keccak.c"
#include "./hash/hash.c"
*/
import "C"

func testHash() {
	var a = "test"
	var h [32]byte

	C.cn_fast_hash(a, 4, &h)
}

func main() {
	testHash()
}
