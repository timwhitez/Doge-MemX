package main

import (
	"encoding/base64"
	"fmt"
)

func main(){
	blacklist := []string{
		//以mimikatz为例，恶意字符串替换
		//warning!! may cause panic!
		"MZ",
		"mimikatz",
		"delpy",
		"benjamin",
		"delpy",
		"vincent",
		"le toux",
		"letoux",
		"A La Vie, A L'Amour",
		"la vie",
		"gentilkiwi",
		"kiwi",
		"creativecommons",
		"oe.eo",
		"pingcastle",
		"mysmartlogon",
		".#####.",
		".## ^ ##.",
		"## / \\ ##",
		"## \\ / ##",
		"'## v ##'",
		"'#####'",
		"This program cannot be run in DOS mode",
		"Stack memory was corrupted",
		"Stack corrupted near unknown variable",
		"Cast to smaller type causing loss of data",
		"Stack memory corruption",
		"Local variable used before initialization",
	}

	for i,_ := range blacklist{
		fmt.Println("lib.DecodeB64(lib.DecodeB64(\""+EncodeB64(EncodeB64(blacklist[i]))+"\")),")
	}


}

func EncodeB64(message string) (retour string) {
	base64Text := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(base64Text, []byte(message))
	return string(base64Text)
}

func DecodeB64(message string) (retour string) {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	base64.StdEncoding.Decode(base64Text, []byte(message))

	return string(base64Text)
}