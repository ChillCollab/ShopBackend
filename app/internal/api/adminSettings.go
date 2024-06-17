package api

import (
	"backend/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (a *App) Settings(c *gin.Context) {
	var config []models.Config

	if err := a.db.Find(&config); err.Error != nil {
		a.logger.Error(err.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error.Error()})
	}
	resultMap := make(map[string]string)
	for _, line := range config {
		if line.Param == "smtp_pass" && line.Value != "" {
			line.Value = "********************"
		}
		resultMap[line.Param] = line.Value
	}

	c.JSON(http.StatusOK, resultMap)
}
