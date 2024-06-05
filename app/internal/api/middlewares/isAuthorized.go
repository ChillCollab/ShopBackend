package middlewares

import (
	"backend/internal/dataBase"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/pkg/authorization"
	"backend/pkg/broker"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
)

type Broker struct {
	*broker.Client
}

func (br *Broker) IsAuthorized(c *gin.Context) {
	lang := language.LangValue(c)
	token := authorization.GetToken(c)
	if token == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	if authorization.JwtParse(token).Email == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	if authorization.CheckTokenExpiration(token) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	array, err := br.RedisGetArray(dataBase.RedisAuthTokens)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.ResponseMsg(false, "db_error", errorCodes.DBError))
		return
	}
	var tokens []models.RejectedToken
	var tokenExist bool
	for _, item := range array {
		var tok models.RejectedToken
		er, errMarshal := json.Marshal(item)
		if errMarshal != nil {
			continue
		}
		errUnmarshal := json.Unmarshal(er, &tok)
		if errUnmarshal != nil {
			continue
		}
		if tok.AccessToken == token {
			tokenExist = true
			break
		}
		tokens = append(tokens, tok)
	}
	if tokenExist {
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
}
