package api

import (
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"github.com/gin-gonic/gin"
	"net/http"
)

// @Summary Get action logs
// @Description Endpoint to get actions log
// @Tags Actions
// @Produce json
// @Success 200 object []models.ActionLogs
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/actions/list [get]
func (a *App) GetActions(c *gin.Context) {
	lang := language.LangValue(c)

	logs := a.db.GetActionLogs()
	if len(logs) == 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(true, language.Language(lang, "action_log_empty"), errorCodes.ActionLogsEmpty))
		return
	}

	c.JSON(http.StatusOK, logs)
}
