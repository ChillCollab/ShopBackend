package routes

import (
	"backend_v1/internal/controllers/authController"

	"github.com/gin-gonic/gin"
)

func Routes(r *gin.Engine) {
	api := r.Group("/api_v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/login", authController.Login)
			auth.POST("/register", authController.Register)
			auth.POST("/activate/send", authController.Send)
			auth.POST("/activate", authController.Activate)
			auth.POST("/logout", authController.Logout)
			auth.POST("/recovery", authController.Recovery)
		}
	}
}
