package config

import (
	"backend/docs"
	dataBase "backend/internal/dataBase/models"
	"backend/internal/routes"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

type app struct {
	server   *gin.Engine
	dataBase *gorm.DB
}

func Run() error {
	app := &app{
		server:   gin.Default(),
		dataBase: dataBase.DB,
	}
	docs.SwaggerInfo.BasePath = "/api_v1"
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:5173/admin"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Authorization", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Access-Control-Allow-Origin"}

	app.server.Use(cors.New(config))
	err := godotenv.Load()
	if err != nil {
		return err
	}

	if err := dataBase.InitDB(); err != nil {
		return err
	}

	routes.Routes(app.server)
	return nil
}
