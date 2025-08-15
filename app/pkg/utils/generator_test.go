package utils

import (
	"strings"
	"testing"

	"github.com/go-playground/assert/v2"
)

// Returns an integer between 0 and 999999
func TestGenerateNumberCodeInRange(t *testing.T) {
	code := GenerateNumberCode()
	if code < 111111 || code > 999999 {
		t.Errorf("Expected code to be between 0 and 999999, but got %d", code)
	}
}

func TestCodeGenLength(t *testing.T) {
	code, err := CodeGen()
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	assert.Equal(t, 19, len(code))
	assert.Equal(t, 3, strings.Count(code, "-"))
}
