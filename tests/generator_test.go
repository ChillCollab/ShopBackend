package tests

import (
	"backend/pkg/utils"
	"encoding/hex"
	"math/rand"
	"strconv"
	"testing"
)

// Mocking the rand.Reader for testing
// MockRandIntn is a mock implementation of rand.Intn for testing GenerateNumberCode function
func MockRandIntn(n int) int {
	return 123456 // Just an arbitrary fixed value for testing
}

// TestGenerateNumberCode tests the GenerateNumberCode function
func TestGenerateNumberCode(t *testing.T) {

	var randIntn = rand.Intn
	// Backup the original rand.Intn function and restore it after the test
	originalRandIntn := randIntn
	defer func() { randIntn = originalRandIntn }()

	// Replace randIntn with our mock function
	randIntn = MockRandIntn

	code := utils.GenerateNumberCode()

	// Check if the generated code matches the expected value
	expected := 123456
	if len(strconv.Itoa(code)) != len(strconv.Itoa(expected)) {
		t.Errorf("GenerateNumberCode() generated %d, expected %d", code, expected)
	}
}

// TestCodeGen tests the CodeGen function
func TestCodeGen(t *testing.T) {
	code := utils.CodeGen()

	// Check if the generated code has the correct format (xxxx-xxxx-xxxx-xxxx)
	if len(code) != 19 || code[4] != '-' || code[9] != '-' || code[14] != '-' {
		t.Errorf("CodeGen() generated code with incorrect format: %s", code)
	}

	// Decode the hexadecimal parts of the code to ensure they are valid hexadecimal
	decodedParts, err := hex.DecodeString(code[:4] + code[5:9] + code[10:14] + code[15:])
	if err != nil {
		t.Errorf("Error decoding hexadecimal parts of the code: %v", err)
	}

	// Check if the length of decodedParts is 8 (each part consists of 2 hexadecimal characters)
	if len(decodedParts) != 8 {
		t.Errorf("Incorrect length of decoded hexadecimal parts: %d", len(decodedParts))
	}

	// Check if each byte in decodedParts is a valid hexadecimal character
	for _, b := range decodedParts {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			t.Errorf("Invalid hexadecimal character: %v", b)
		}
	}
}
