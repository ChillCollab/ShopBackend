package utils

import (
	"encoding/hex"
	"fmt"
	"math/rand"
)

func GenerateNumberCode() int {
	code := rand.Intn(1000000)
	return code
}

func CodeGen() string {

	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}

	// Convert bytes to hexadecimal string
	code := hex.EncodeToString(bytes)

	// Format the code as "xxxx-xxxx-xxxx-xxxx"
	formattedCode := fmt.Sprintf("%s-%s-%s-%s", code[0:4], code[4:8], code[8:12], code[12:16])

	return formattedCode
}

func LongCodeGen() string {

	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}

	// Convert bytes to hexadecimal string
	code := hex.EncodeToString(bytes)

	// Format the code as "xxxx-xxxx-xxxx-xxxx"
	formattedCode := fmt.Sprintf("%s-%s-%s-%s-%s-%s", code[0:4], code[4:8], code[8:12], code[12:16], code[16:20], code[20:24])

	return formattedCode
}
