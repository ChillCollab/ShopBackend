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

	srv.Logger.Info("Starting server...")

	err := godotenv.Load("../.env")
	if err != nil {
		panic("Env can't be loaded")
	}
	srv.Logger.Info("Env loaded")

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
	srv.Logger.Info("DB connected")

	api.New(srv).Routes(r)
	srv.Logger.Info("API created")

	srv.Logger.Info("Server starting on: ")
	srv.Logger.Info("PORT: " + os.Getenv("APP_PORT"))
	srv.Logger.Info("DB_HOST: " + os.Getenv("DB_HOST"))
	srv.Logger.Info("DB_PORT: " + os.Getenv("DB_PORT"))
	srv.Logger.Info("ACCESS_ALIVE: " + os.Getenv("ACCESS_ALIVE"))
	srv.Logger.Info("REFRESH_ALIVE: " + os.Getenv("REFRESH_ALIVE"))

	runErr := r.Run(":" + os.Getenv("APP_PORT"))
	if runErr != nil {
		panic(runErr)
	}

}
