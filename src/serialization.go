package main

/*
#cgo LDFLAGS: -L ../lib -lmonerocrypto
#include "./crypto/keys.h"
#include "./crypto/hash/hash.h"
#include "./utils/utils.h"
*/
import "C"

import (
	"C"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

//!!Serialization functions currently do NOT check for errors
//Not ready for production!!

/********************************************
*			JSON Serializing				*
*********************************************/

/*---------- TxOut ----------*/

func (in *TxOut) MarshallJSON() ([]byte, error) {
	in.Target.DestString = hex.EncodeToString(in.Target.Dest[:])
	return json.MarshalIndent(in, "", "\t")
}

func (in *TxOut) UnmarshallJSON(data []byte) error {
	err := json.Unmarshal(data, in)
	temp, _ := hex.DecodeString(in.Target.DestString)
	copy(in.Target.Dest[:], temp[:])
	return err
}

/*---------- EcdhInfo ----------*/

func (in *EcdhInfo) MarshallJSON() ([]byte, error) {
	in.MaskString = hex.EncodeToString(in.Mask[:])
	in.AmountString = hex.EncodeToString(in.Amount[:])
	return json.MarshalIndent(in, "", "\t")
}

func (in *EcdhInfo) UnmarshallJSON(data []byte) error {
	err := json.Unmarshal(data, in)
	if err != nil {
		return err
	}
	mask, err := hex.DecodeString(in.MaskString)
	amt, err := hex.DecodeString(in.AmountString)
	copy(in.Mask[:], mask[:])
	copy(in.Amount[:], amt[:])
	return err
}

/*---------- RctSignatures ----------*/

func (in *RctSignatures) MarshallJSON() ([]byte, error) {
	for i := range in.OutPk {
		in.OutPkString[i] = hex.EncodeToString(in.OutPk[i][:])
	}
	if in.RctType == 2 {
		for i := range in.PseudoOuts {
			in.PseudoOutString[i] = hex.EncodeToString(in.PseudoOuts[i][:])
		}
	}
	return json.MarshalIndent(in, "", "\t")
}

func (in *RctSignatures) UnmarshallJSON(data []byte) error {
	err := json.Unmarshal(data, in)
	if err != nil {
		return err
	}
	for i := range in.OutPkString {
		temp, _ := hex.DecodeString(in.OutPkString[i])
		copy(in.OutPk[i][:], temp[:])
	}

	if in.RctType == 2 {
		for i := range in.PseudoOutString {
			temp, _ := hex.DecodeString(in.PseudoOutString[i])
			copy(in.PseudoOuts[i][:], temp[:])
		}
	}
	return err
}

/*---------- RangeSig ----------*/

func (in *RangeSig) MarshallJSON() ([]byte, error) {
	var buffer bytes.Buffer

	for i := range in.Ci {
		//in.CiString += hex.EncodeToString(in.Ci[i][:])
		buffer.WriteString(hex.EncodeToString(in.Ci[i][:]))
	}
	in.CiString = buffer.String()

	buffer.Reset()
	for i := range in.Asig.s0 {
		buffer.WriteString(hex.EncodeToString(in.Asig.s0[i][:]))
	}
	for i := range in.Asig.s1 {
		buffer.WriteString(hex.EncodeToString(in.Asig.s1[i][:]))
	}
	buffer.WriteString(hex.EncodeToString(in.Asig.e0[:]))
	in.AsigString = buffer.String()

	return json.MarshalIndent(in, "", "\t")
}

func (in *RangeSig) UnmarshallJSON(data []byte) error {
	err := json.Unmarshal(data, in)
	if err != nil {
		return err
	}
	Asig, _ := hex.DecodeString(in.AsigString)
	Ci, _ := hex.DecodeString(in.CiString)
	//Asig contains 64 s0, 64 s1 and e0. Each of these is 32 bytes
	if len(Asig) != (1+64*2)*32 {
		return errors.New("Asig is not the correct length")
	}
	if len(Ci) != (64 * 32) {
		return errors.New("Ci is not the correct length")
	}

	for i := 0; i < 64; i++ {
		copy(in.Ci[i][:], Ci[i*32:(i+1)*32])
	}

	for i := 0; i < 128; i++ {
		if i < 64 {
			copy(in.Asig.s0[i][:], Asig[i*32:(i+1)*32])
		} else {
			copy(in.Asig.s1[i-64][:], Asig[i*32:(i+1)*32])
		}
	}

	copy(in.Asig.e0[:], Asig[32*128:32*129])
	return err
}

/********************************************
*		Transaction/hashing serializing     *
*********************************************/

//SerializeTx will serialize the transaction
//ADD headeronly option AND serialize signatures
func (prefix TransactionPrefix) SerializeTx() string {
	var buffer bytes.Buffer
	temp := ""

	//Write the transaction version
	C.write_varint(C.CString(temp), C.ulong(prefix.Version))
	buffer.WriteString(temp)

	//Write the unlock time (usually 0)
	temp = ""
	C.write_varint(C.CString(temp), C.ulong(prefix.UnlockTime))
	buffer.WriteString(temp)

	//Write the number of inputs the tx uses
	temp = ""
	inputsLen := len(prefix.Inputs)
	C.write_varint(C.CString(temp), C.ulong(inputsLen))
	buffer.WriteString(temp)

	var i, j int
	//i is the input number
	for i = 0; i < inputsLen; i++ {
		input := prefix.Inputs[i]
		buffer.WriteByte(0x02) //txin_to_key is 02
		//Write the amount of this input (0 for ringct)
		temp = ""
		C.write_varint(C.CString(temp), C.ulong(input.Amount))
		buffer.WriteString(temp)

		temp = ""
		offsetsLen := len(input.KeyOffsets)
		C.write_varint(C.CString(temp), C.ulong(offsetsLen))
		buffer.WriteString(temp) //Write the number of offsets (equal to size of ring)

		//j is the key offset number for this input
		for j = 0; j < offsetsLen; j++ {
			temp = ""
			C.write_varint(C.CString(temp), C.ulong(input.KeyOffsets[j]))
			buffer.WriteString(temp) //Write the key offset number
		}

		//Write the key image
		buffer.WriteString(string(input.KeyImage[:]))
	}

	//Write the number of outputs the tx makes
	temp = ""
	outputsLen := len(prefix.Outputs)
	C.write_varint(C.CString(temp), C.ulong(outputsLen))
	buffer.WriteString(temp)

	//i is the output number
	for i = 0; i < outputsLen; i++ {
		output := prefix.Outputs[i]
		//Write the amount of this output (0 for ringct)
		temp = ""
		C.write_varint(C.CString(temp), C.ulong(output.Amount))
		buffer.WriteString(temp)

		buffer.WriteByte(0x02) //txout_to_key is 02
		buffer.WriteString(string(output.Target.Dest[:]))
	}

	//Prepend the extra byte length
	temp = ""
	C.write_varint(C.CString(temp), C.ulong(len(prefix.Extra)))
	buffer.WriteString(temp)

	//Write extra bytes
	//buffer.WriteString(hex.EncodeToString(prefix.Extra[:]))
	buffer.WriteString(string(prefix.Extra[:]))

	return buffer.String()
}

//SerializeRct will serialize the rctsignature used for hashing
func (rv RctSignatures) SerializeRct() (string, error) {
	var buffer bytes.Buffer
	temp := ""

	//Write the ring type
	C.write_varint(C.CString(temp), C.ulong(rv.RctType))
	buffer.WriteString(temp)

	//Write the fee
	temp = ""
	C.write_varint(C.CString(temp), C.ulong(rv.Fee))
	buffer.WriteString(temp)

	//If we are using RCTTypeSimple, write the pseudoOuts
	if rv.RctType == 2 {
		for i := 0; i < len(rv.PseudoOuts); i++ {
			buffer.WriteString(string(rv.PseudoOuts[i][:]))
		}
	}

	if len(rv.Ecdhs) != len(rv.PseudoOuts) {
		return "", errors.New("Outpk and ecdh have different lengths")
	}

	//Write the ecdhInfo
	for i := 0; i < len(rv.Ecdhs); i++ {
		ecdh := rv.Ecdhs[i]
		buffer.WriteString(string(ecdh.Mask[:]))
		buffer.WriteString(string(ecdh.Amount[:]))
	}

	//Write the outPk
	for i := 0; i < len(rv.OutPk); i++ {
		buffer.WriteString(string(rv.OutPk[i][:]))
	}

	return buffer.String(), nil
}

//SerializeRangeProofs will serialize the range proofs in rv
func (rv RctsigPrunable) SerializeRangeProofs() (string, error) {
	var buffer bytes.Buffer

	//Iterate over every range proof
	for sigIndex := 0; sigIndex < len(rv.RangeSigs); sigIndex++ {
		sig := rv.RangeSigs[sigIndex]

		//Iterate every s0 and then every s1
		for i := 0; i < 64; i++ {
			buffer.WriteString(string(sig.Asig.s0[i][:]))
		}
		for i := 0; i < 64; i++ {
			buffer.WriteString(string(sig.Asig.s1[i][:]))
		}
		//Write the e0 value for this proof
		buffer.WriteString(string(sig.Asig.e0[:]))

		//Write all 64 Ci values
		for ciIndex := 0; ciIndex < 64; ciIndex++ {
			buffer.WriteString(string(sig.Ci[ciIndex][:]))
		}
	}

	return buffer.String(), nil
}

func serialTest() {
	fmt.Println("===Serialization test===")
	/*
		var txout TxOutToKey
		for i := range txout.Dest {
			txout.Dest[i] = 0x00 + byte(i)
		}
		//b, err := json.MarshalIndent(txout, "", "\t")
		b, err := txout.MarshalJSON()
		if err != nil {
			fmt.Println("error:", err)
		}
		os.Stdout.Write(b)

		var test1 TxOutToKey
		test1.UnmarshalJSON(b)
		fmt.Println(test1)

		var out TxOut
		out.Amount = 300
		for i := range out.Target.Dest {
			out.Target.Dest[i] = 0x32 + byte(i)
		}
		b, err = out.MarshallJSON()
		os.Stdout.Write(b)
	*/

	var out TxOut
	for i := range out.Target.Dest {
		out.Target.Dest[i] = 0x32 + byte(i)
	}
	b, err := out.MarshallJSON()
	if err != nil {
		fmt.Println(err)
	}
	os.Stdout.Write(b)

	var test TxOut
	test.UnmarshallJSON(b)
	fmt.Println(test)
}
