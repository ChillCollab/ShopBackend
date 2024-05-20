package config

import (
	"backend/pkg/logger"
	"github.com/joho/godotenv"
)

func Get() error {
	log := logger.GetLogger()
	err := godotenv.Load(".env")
	if err != nil {
		log.Error("error loading .env file: ", err)
	}

	return nil
}
