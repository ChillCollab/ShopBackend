package middlewares

import (
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/pkg/authorization"
	"github.com/gin-gonic/gin"
	"net/http"
)

func IsAdmin(c *gin.Context) {
	lang := language.LangValue(c)
	token := authorization.GetToken(c)
	parsedToken := authorization.JwtParse(token)
	if parsedToken.Role.(float64) < 1 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
}
