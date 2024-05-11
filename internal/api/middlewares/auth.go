package middlewares

import (
	"backend/internal/dataBase"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/pkg/broker"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

type Broker struct {
	*broker.Client
}

func (br *Broker) IsAuthorized(c *gin.Context) {
	lang := language.LangValue(c)
	token := CheckAuth(c, false)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		c.Abort()
	}
	tokenData := JwtParse(token)
	if tokenData.Email == nil {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		c.Abort()
	}

	array, err := br.RedisGetArray(dataBase.RedisAuthTokens)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, "db_error", errorCodes.DBError))
		return
	}
	var tokens []models.AuthToken
	for _, item := range array {
		var tok models.AuthToken
		er, errMarshal := json.Marshal(item)
		if errMarshal != nil {
			continue
		}
		errUnmarshal := json.Unmarshal(er, &tok)
		if errUnmarshal != nil {
			continue
		}
		fmt.Println(tok)
		tokens = append(tokens, tok)
	}
}
func IsAdmin() {
	fmt.Println("IsAdmin")
}
