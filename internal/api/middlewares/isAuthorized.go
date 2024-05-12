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
	token := GetToken(c)
	if token == "" {
		fmt.Println(1)
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	if JwtParse(token).Email == nil {
		fmt.Println(2)
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	if CheckTokenExpiration(token) {
		fmt.Println(111)
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	array, err := br.RedisGetArray(dataBase.RedisAuthTokens)
	if err != nil {
		fmt.Println(3)
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
			fmt.Println(tok)
			fmt.Println(token)
			tokenExist = true
			break
		}
		tokens = append(tokens, tok)
	}
	if tokenExist {
		fmt.Println(4)
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
}
func IsAdmin() {
	fmt.Println("IsAdmin")
}
