package utils

import (
	"encoding/json"
	"reflect"

	"github.com/gin-gonic/gin"
)

func JsonChecker(s interface{}, rawData []byte, c *gin.Context) string {
	var requestData map[string]interface{}
	if err := json.Unmarshal(rawData, &requestData); err != nil {
		return "Incorrect JSON data"
	}

	structType := reflect.TypeOf(s)

	structFields := make(map[string]bool)
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		jsonTag := field.Tag.Get("json")
		structFields[jsonTag] = true
	}

	for key := range requestData {
		if !structFields[key] {
			return "Invalid request fields: " + key
		}
	}

	return ""
}
