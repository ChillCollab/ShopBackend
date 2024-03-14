package handlers

import "github.com/gin-gonic/gin"

func ErrMsg(err bool, message string, code int) gin.H {
	if code == 0 {
		return gin.H{
			"success": err,
			"message": message,
		}
	} else {
		return gin.H{
			"code":    code,
			"success": err,
			"message": message,
		}
	}
}
