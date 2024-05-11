package middlewares

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

func IsAuthorized(c *gin.Context) {
	token := CheckAuth(c, false)
	fmt.Println(token)
}
