package utils

import "regexp"

func PhoneNumberValidator(phoneNumber string) bool {
	regex := `^\+[0-9]{1,15}$`
	matched, _ := regexp.MatchString(regex, phoneNumber)
	return matched
}

func ValidateLogin(login string) bool {
	// Regular expression to match logins with only letters and numbers, with a maximum of 32 characters
	regex := `^[a-zA-Z0-9]{1,32}$`
	matched, _ := regexp.MatchString(regex, login)
	return matched
}
