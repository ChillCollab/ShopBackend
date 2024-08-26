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

func (a *App) SetSMTP(c *gin.Context) {
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

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "smtp_settings_updated"), 0))

	tokenData := authorization.JwtParse(c.GetHeader("Authorization"))
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
}
