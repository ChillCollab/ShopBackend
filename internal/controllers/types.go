package controllers

import (
	"backend/pkg/logger"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Controller struct {
	srv    *gin.Engine
	db     *gorm.DB
	logger logger.Logger
}

func New(srv *gin.Engine, db *gorm.DB, logger logger.Logger) Controller {
	return Controller{
		srv:    srv,
		db:     db,
		logger: logger,
	}
}
