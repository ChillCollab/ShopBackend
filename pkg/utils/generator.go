package utils

import (
	"encoding/hex"
	"fmt"
	"math/rand"
)

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
