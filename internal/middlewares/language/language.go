package language

import (
	"backend/pkg/logger"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func Language(lang string, key string) string {
	logger := logger.GetLogger()

	var filePath string
	if lang == "ru" {
		filePath = "../languages/ru.json"
	} else {
		filePath = "../languages/en.json"
	}

	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	var data map[string]interface{}
	err = json.Unmarshal(fileContent, &data)
	if err != nil {
		log.Fatal(err)
	}

	if data[key] == nil {
		logger.Error("key " + key + " not found")
		return ""
	}

	value := data[key].(string)
	return value
}

func LangValue(c *gin.Context) string {
	languageCookie, err := c.Request.Cookie("lang")

	if err != nil || languageCookie.Value != "ru" {
		languageCookie = &http.Cookie{
			Name:  "lang",
			Value: "en",
		}

		http.SetCookie(c.Writer, languageCookie)
	}
	return languageCookie.Value
}
