package server

import (
	"backend/pkg/logger"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type App struct {
	Server   *gin.Engine
	DataBase *gorm.DB
	Logger   logger.Logger
}

func New(server *gin.Engine, dataBase *gorm.DB, logger logger.Logger) *App {
	return &App{
		Server:   server,
		DataBase: dataBase,
		Logger:   logger,
	}
}
