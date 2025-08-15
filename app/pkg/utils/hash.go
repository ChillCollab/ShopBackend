package utils

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"unicode"
)

func Hash(data string) string {
	hasher := sha512.New()

	hasher.Write([]byte(data + os.Getenv("SALT_PASSWORD")))

	// Get the hashed bytes
	hashedBytes := hasher.Sum(nil)

	// Convert the hashed bytes to a hexadecimal string
	hashedString := hex.EncodeToString(hashedBytes)

	return hashedString
}

func PasswordChecker(password string) (bool, bool) {
	//Что-то мне подсказывает что можно это сделать иначе, например регуляркой
	if len(password) < 8 {
		return false, false
	}

	hasDigit := false
	hasSymbol := false

	for _, char := range password {
		if unicode.IsDigit(char) {
			hasDigit = true
		} else if unicode.IsSymbol(char) || unicode.IsPunct(char) {
			hasSymbol = true
		}
	}

	return hasDigit, hasSymbol
}
