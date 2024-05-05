package main

import (
	"backend/docs"
	server "backend/internal"
	api "backend/internal/api"
	dataBase "backend/internal/dataBase/models"
	"backend/pkg/logger"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {

	srv := server.New(gin.Default(), dataBase.DB, logger.GetLogger())

	err := godotenv.Load("../.env")
	if err != nil {
		panic("Env can't be loaded")
	}

	docs.SwaggerInfo.BasePath = "/api_v1"
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:5173/admin"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Authorization", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Access-Control-Allow-Origin"}

	r := gin.Default()
	r.Use(cors.New(config))

	if err := dataBase.InitDB(); err != nil {
		panic(err)
	}
	api.New(srv).Routes(r)

	runErr := r.Run(":" + os.Getenv("APP_PORT"))
	if runErr != nil {
		panic(runErr)
	}

}
