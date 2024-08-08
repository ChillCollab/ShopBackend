package utils

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func GenerateNumberCode() int {
	// Инициализация генератора псевдослучайных чисел
	rand.Seed(time.Now().UnixNano())

	// Генерация числа от 100000 до 999999
	code := rand.Intn(900000) + 100000
	return code
}

func CodeGen() (string, error) {

	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Convert bytes to hexadecimal string
	code := hex.EncodeToString(bytes)

	// Format the code as "xxxx-xxxx-xxxx-xxxx"
	formattedCode := fmt.Sprintf("%s-%s-%s-%s", code[0:4], code[4:8], code[8:12], code[12:16])

	return formattedCode, nil
}

func LongCodeGen() (string, error) {

	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Convert bytes to hexadecimal string
	code := hex.EncodeToString(bytes)

	// Format the code as "xxxx-xxxx-xxxx-xxxx"
	formattedCode := fmt.Sprintf("%s-%s-%s-%s-%s-%s", code[0:4], code[4:8], code[8:12], code[12:16], code[16:20], code[20:24])

	return formattedCode, nil
}
