package language

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func Language(lang string, key string) string {
	var filePath string
	if lang == "ru" {
		filePath = "./languages/ru.json"
	} else {
		filePath = "./languages/en.json"
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

	value := data[key].(string)
	return value
}

func LangValue(c *gin.Context) string {
	language, err := c.Request.Cookie("lang")

	fmt.Println(language.Value)

	if err != nil || language.Value != "ru" {
		language = &http.Cookie{
			Name:  "lang",
			Value: "en",
		}
	}

	return language.Value
}
