package handlers

import "github.com/gin-gonic/gin"

func ErrMsg(success bool, message string, code int) gin.H {
	if code == 0 {
		return gin.H{
			"success": success,
			"message": message,
		}
	} else {
		return gin.H{
			"code":    code,
			"success": success,
			"message": message,
		}
	}
}
