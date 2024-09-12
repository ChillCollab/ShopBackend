package api

import (
	"backend/internal/dataBase"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/models/requestData"
	"backend/pkg/authorization"
	"backend/pkg/client"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (a *App) GetConfig(c *gin.Context) {
	lang := language.LangValue(c)

	tx := a.db.Begin()

	var configs []models.Config
	if err := tx.Find(&configs).Error; err != nil {
		a.logger.Errorf("failed to retrieve configs: %v", err)
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "error_get_config"), errorCodes.ErrorGetConfig))
		return
	}
	if err := tx.Commit(); err.Error != nil {
		a.logger.Errorf("failed to commit transaction: %v", err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "internal_error"), errorCodes.DBError))
		return
	}

	// Create a map to store param-value pairs
	configMap := make(map[string]string)
	for _, config := range configs {
		configMap[config.Param] = config.Value
	}

	// Return the map as a JSON response
	c.JSON(http.StatusOK, configMap)
}

func (a *App) UpdateSMTP(c *gin.Context) {
	lang := language.LangValue(c)

	var smtpData requestData.SmtpSettings

	if err := c.ShouldBindJSON(&smtpData); err != nil {
		a.logger.Logger.Errorf("error bind json: %v", err)
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	if err := a.db.SmtpSet(smtpData); err != nil {
		a.logger.Logger.Errorf("error set smtp: %v", err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "internal_error"), errorCodes.DBError))
		return
	}

	tokenData := authorization.JwtParse(authorization.GetToken(c))
	fullUserInfo, errInfo := a.db.UserInfo(tokenData.Email, tokenData.Email)
	if errInfo != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	a.db.AttachAction(models.ActionLogs{
		Action:  "Change settings of SMTP server",
		Login:   fullUserInfo.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "smtp_settings_updated"), 0))

}
