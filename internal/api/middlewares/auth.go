package middlewares

import (
	"backend/pkg/broker"
	"fmt"
	"github.com/gin-gonic/gin"
)

type Broker struct {
	*broker.Client
}

func (br *Broker) IsAuthorized(c *gin.Context) {
	token := CheckAuth(c, false)
	data := JwtParse(token)
	fmt.Println(data.Email)
	fmt.Println("dadsad")
}
