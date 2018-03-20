package main

/*
#cgo LDFLAGS: -L ../lib -lmonerocrypto
#include "./crypto/keys.h"
*/
import (
	"C"
)
import (
	"fmt"
	"log"
)

func main() {

	keys := GenKeys()
	fmt.Printf("sk spend: %x\n", keys.skSpend)
	fmt.Printf("pk spend: %x\n", keys.pkSpend)
	fmt.Printf("sk view: %x\n", keys.skView)
	fmt.Printf("pk view: %x\n", keys.pkView)
	fmt.Printf("address: %s\n", keys.address)
	fmt.Printf("%s\n", SecretToMnemonic(keys.skSpend))

	stealthTest()
	spend, view, err := DecodeAddress(keys.address)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("spend: %x\nview: %x\n", spend, view)
}
