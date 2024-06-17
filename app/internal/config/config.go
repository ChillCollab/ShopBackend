package config

import (
	"fmt"

	"github.com/joho/godotenv"
)

func Get() error {
	err := godotenv.Load(".env")
	if err != nil {
		return fmt.Errorf("error loading .env file: %v", err)
	}

	return nil
}
