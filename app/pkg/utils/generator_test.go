package utils

import (
	"fmt"
	"github.com/go-playground/assert/v2"
	"strings"
	"testing"
)

// Returns an integer between 0 and 999999
func TestGenerateNumberCodeInRange(t *testing.T) {
	code := GenerateNumberCode()
	if code < 111111 || code > 999999 {
		t.Errorf("Expected code to be between 0 and 999999, but got %d", code)
	}
}

func TestCodeGenLength(t *testing.T) {
	code := CodeGen()
	fmt.Println(code)
	assert.Equal(t, 19, len(code))
	assert.Equal(t, 3, strings.Count(code, "-"))
}
