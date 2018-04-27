package main

/*
#cgo LDFLAGS: -L ../lib -lmonerocrypto
#include "./crypto/keys.h"
#include "./crypto/hash/hash.h"
#include "./crypto/stealth.h"
#include "./crypto/subaddress.h"
*/
import "C"
import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"strings"
	"unsafe"

	base58 "./base58"
)

const numWords uint32 = 1626
const moneroMainnetPreix = 0x12     //18
const moneroSubaddressPrefix = 0x2A //42

//KeyRing holds all required information for the base key pair of an account
type KeyRing struct {
	skSpend Key //b
	skView  Key //a
	pkSpend Key //B
	pkView  Key //A
	address string
}

//GenKeys generates new private spend and view keys and their corresponding public keys,
//generates the public address and returns a KeyRing
func GenKeys() KeyRing {
	var keys KeyRing
	C.generate_keys(GoKeyToUcharPtr(&keys.pkSpend), GoKeyToUcharPtr(&keys.skSpend))
	C.hash_to_scalar(unsafe.Pointer(&keys.skSpend), 32, GoKeyToUcharPtr(&keys.skView))
	C.secret_to_public(GoKeyToUcharPtr(&keys.pkView), GoKeyToUcharPtr(&keys.skView))

	keys.address = CreateAddress(keys.pkSpend, keys.pkView, false)
	return keys
}

//CreateAddress creates the public address of the given public spend and view keys
//subaddr is true if we are encoding a subaddress, false otherwise
func CreateAddress(spend, view Key, subaddr bool) string {
	var toHash [65]byte
	var addressBytes [69]byte
	if subaddr {
		toHash[0] = moneroSubaddressPrefix
		addressBytes[0] = moneroSubaddressPrefix
	} else {
		toHash[0] = moneroMainnetPreix
		addressBytes[0] = moneroMainnetPreix
	}
	for i := 0; i < 32; i++ {
		toHash[i+1] = spend[i]
		toHash[i+1+32] = view[i]
		addressBytes[i+1] = spend[i]
		addressBytes[i+1+32] = view[i]
	}

	var hashResult Scalar
	C.hash_no_reduce(unsafe.Pointer(&toHash), 65, GoScalarToUcharPtr(&hashResult))
	copy(addressBytes[65:69], hashResult[0:4]) //Checksum takes up last 4 bytes

	var data [9]string
	for i := 0; i < 8; i++ {
		data[i] = base58.Encode(addressBytes[8*i : 8*i+8])
		for len(data[i]) < 11 {
			data[i] += "1"
		}
	}
	data[8] = base58.Encode(addressBytes[64:69]) //Last 5 byte block
	for len(data[8]) < 7 {
		data[8] += "1"
	}

	return strings.Join(data[:], "")
}

//DecodeAddress will take in a standard 95-character Monero address and return
//the public spend and view keys, or an error if the checsum is invalid
//Staticly uses the Monero mainnet network byte
func DecodeAddress(address string) (spendKey, viewKey Key, err error) {
	if len(address) != 95 {
		return spendKey, viewKey, errors.New("Address is not 95 characters")
	}
	var data [69]byte
	for i := 0; i < 8; i++ {
		temp := base58.Decode(address[i*11 : i*11+11])
		copy(data[i*8:(i+1)*8], temp)
	}
	temp := base58.Decode(address[88:95])
	copy(data[64:69], temp)

	if data[0] != moneroMainnetPreix && data[0] != moneroSubaddressPrefix {
		return spendKey, viewKey, errors.New("Invalid network byte")
	}

	checksum := data[65:69]
	var hashResult Scalar
	C.hash_no_reduce(unsafe.Pointer(&data), 65, GoScalarToUcharPtr(&hashResult))
	if !(bytes.Compare(checksum, hashResult[0:4]) == 0) {
		return spendKey, viewKey, errors.New("Checksum does not match")
	}

	copy(spendKey[:], data[1:33])
	copy(viewKey[:], data[33:65])

	return
}

func getChecksumIndex(words [24]string) uint32 {
	var prefixes string
	for i := 0; i < len(words); i++ {
		prefixes += words[i][0:3] //Current algorithm takes first 3 letters
	}
	res := crc32.ChecksumIEEE([]byte(prefixes))
	return (res % uint32(len(words)))
}

//SecretToMnemonic will convert a secret key (32 bytes) to a 25 word mnemonic
//The first 24 words contain the actual data, and the 25th is a checksum
func SecretToMnemonic(src Key) string {
	var seed string
	var words [24]string

	file, err := os.Open("./words.txt")
	if err != nil {
		log.Fatal(err.Error())
	}
	var dictionary [1626]string
	scanner := bufio.NewScanner(file)
	i := 0
	for scanner.Scan() {
		dictionary[i] = scanner.Text()
		i++
	}

	//Get the words in 4 byte chunks, as 4 bytes -> 3 words
	for j := 0; j < 8; j++ {
		var curr uint32

		slice := []byte{src[j*4], src[j*4+1], src[j*4+2], src[j*4+3]}
		curr = binary.LittleEndian.Uint32(slice)

		w1 := curr % numWords
		w2 := ((curr / numWords) + w1) % numWords
		w3 := (((curr / numWords) / numWords) + w2) % numWords

		words[j*3] = dictionary[w1]
		words[j*3+1] = dictionary[w2]
		words[j*3+2] = dictionary[w3]
	}
	checksum := getChecksumIndex(words)
	checksumWord := words[checksum]
	seed = strings.Join(words[:], " ")
	seed += " "
	seed += checksumWord

	return seed
}

func stealthTest() {
	// https://monero.stackexchange.com/questions/1409/constructing-a-stealth-monero-address/
	// https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-part-2-stealth-addresses
	Abytes, err := hex.DecodeString("6bb8297dc3b54407ac78ffa4efa4afbe5f1806e5e41aa56ae98c2fe53032bb4b")
	if err != nil {
		log.Fatal(err.Error())
	}
	Bbytes, err := hex.DecodeString("3bcb82eecc13739b463b386fc1ed991386a046b478bf4864673ca0a229c3cec1")
	if err != nil {
		log.Fatal(err.Error())
	}
	rBytes, err := hex.DecodeString("c91ae3053f640fcad393fb6c74ad9f064c25314c8993c5545306154e070b1f0f")
	if err != nil {
		log.Fatal(err.Error())
	}
	aBytes, err := hex.DecodeString("fadf3558b700b88936113be1e5342245bd68a6b1deeb496000c4148ad4b61f02")
	if err != nil {
		log.Fatal(err.Error())
	}
	bBytes, err := hex.DecodeString("c595161ea20ccd8c692947c2d3ced471e9b13a18b150c881232794e8042bf107")
	if err != nil {
		log.Fatal(err.Error())
	}

	var a, b, A, B Key
	var r Scalar
	copy(a[:], aBytes)
	copy(b[:], bBytes)
	copy(A[:], Abytes)
	copy(B[:], Bbytes)
	copy(r[:], rBytes)

	var stealth C.stealth_address
	copy(CscalarToByteSlice(&stealth.r)[:], r[:])
	fmt.Printf("r: %x\n", stealth.r)
	C.generateStealth(GoKeyToUcharPtr(&A), GoKeyToUcharPtr(&B), &stealth, false, 0, false)
	fmt.Printf("R: %x\n", stealth.R)
	fmt.Printf("pub: %x\n", stealth.pub)
	fmt.Printf("b: %x\n", b)

	res := C.isStealthMine(nil, CpointToCuchar(&stealth.pub), CpointToCuchar(&stealth.R), GoKeyToUcharPtr(&a), GoKeyToUcharPtr(&B), 0)
	fmt.Println(res)

	if res {
		var priv Key
		C.getStealthKey(GoKeyToUcharPtr(&priv), CpointToCuchar(&stealth.R), GoKeyToUcharPtr(&a), GoKeyToUcharPtr(&b), 0)
		fmt.Printf("x: %x\n", priv)
	}
}

func subaddressTest() {
	fmt.Println("===Subaddress test===")
	ring := GenKeys()
	var C, D, Dprime Key
	index := C.generate_subaddress_index(1, 0)
	C.generate_subaddress(GoKeyToUcharPtr(&D), GoKeyToUcharPtr(&C), GoKeyToUcharPtr(&ring.pkSpend), GoKeyToUcharPtr(&ring.skView), index)
	addr := CreateAddress(D, C, true)
	fmt.Println(addr)
	fmt.Printf("C: %x\nD: %x\n", C, D)

	var stealth C.stealth_address
	C.generateStealth(GoKeyToUcharPtr(&C), GoKeyToUcharPtr(&D), &stealth, true, 0, true)
	fmt.Printf("R: %x\n", stealth.R)
	fmt.Printf("pub: %x\n", stealth.pub)

	res := C.isStealthMine(GoKeyToUcharPtr(&Dprime), CpointToCuchar(&stealth.pub), CpointToCuchar(&stealth.R), GoKeyToUcharPtr(&ring.skView), GoKeyToUcharPtr(&ring.pkSpend), 0)
	fmt.Println(res)
	fmt.Printf("Dprime: %x\n", Dprime)

	var priv, pre Key
	C.getStealthKey(GoKeyToUcharPtr(&pre), CpointToCuchar(&stealth.R), GoKeyToUcharPtr(&ring.skView), GoKeyToUcharPtr(&ring.skSpend), 0)
	C.subaddress_get_stealth_secret(GoKeyToUcharPtr(&priv), GoKeyToUcharPtr(&pre), GoKeyToUcharPtr(&ring.skView), index)
	fmt.Printf("priv: %x\n", priv)

	var pub Key
	C.secret_to_public(GoKeyToUcharPtr(&pub), GoKeyToUcharPtr(&priv))
	fmt.Printf("Pub (=pub?): %x\n", pub)
}
