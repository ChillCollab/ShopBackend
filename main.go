package main

import (
	"backend/api/routes"
	"backend/docs"
	dataBase "backend/internal/dataBase/models"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

func main() {
	r := gin.Default()

	docs.SwaggerInfo.BasePath = "/api_v1"

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:5173/admin"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Authorization", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Access-Control-Allow-Origin"}

	r.Use(cors.New(config))
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

	r.GET("/swagger/*any",
		ginSwagger.WrapHandler(swaggerfiles.Handler,
			ginSwagger.DefaultModelsExpandDepth(1),
			ginSwagger.PersistAuthorization(true),
		),
	)

	runErr := r.Run(":" + os.Getenv("APP_PORT"))
	if runErr != nil {
		panic(runErr)
	}
}
