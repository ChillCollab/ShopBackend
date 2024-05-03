package main

import (
	config "backend/internal"
	dataBase "backend/internal/dataBase/models"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

type app struct {
	server   *gin.Engine
	dataBase *gorm.DB
}

func main() {

	app := &app{
		server:   gin.Default(),
		dataBase: dataBase.DB,
	}

	if err := config.Run(); err != nil {
		log.Fatalf("error run config: %v", err)
	}

	runErr := app.server.Run(":" + os.Getenv("APP_PORT"))
	if runErr != nil {
		panic(runErr)
	}
}
