package main

import (
	"backend_v1/api/routes"
	dataBase "backend_v1/internal/dataBase/models"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	r := gin.Default()

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dbConfig := dataBase.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	}

	dataBase.InitDB(dbConfig)

	routes.Routes(r)

	runErr := r.Run(":" + os.Getenv("APP_PORT"))
	if runErr != nil {
		panic(runErr)
	}
}
