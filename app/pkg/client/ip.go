package client

import "github.com/gin-gonic/gin"

func GetIP(c *gin.Context) string {
	ip := c.Request.Header.Get("X-Real-Ip")
	if ip == "" {
		ip = c.Request.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = c.ClientIP()
		if ip == "::1" {
			ip = "127.0.0.1"
		}
	}
	return ip
}
