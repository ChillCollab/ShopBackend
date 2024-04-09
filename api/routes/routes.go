package routes

import (
	"backend_v1/internal/controllers/adminController"
	"backend_v1/internal/controllers/authController"
	"backend_v1/internal/controllers/userController"

	"github.com/gin-gonic/gin"
)

func Routes(r *gin.Engine) {
	api := r.Group("/api_v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/login", authController.Login)
			auth.POST("/refresh", authController.Refresh)
			auth.POST("/register", authController.Register)
			auth.POST("/activate/send", authController.Send)
			auth.POST("/activate", authController.Activate)
			auth.POST("/logout", authController.Logout)
			auth.POST("/recovery", authController.Recovery)
			auth.POST("/register/check", authController.CheckRegistrationCode)
		}
		user := api.Group("/user")
		{
			user.GET("/info", userController.Info)
			user.POST("/changepass", userController.ChangePassword)
		}

		admin := api.Group("/admin")
		{
			admin.GET("/users", adminController.Users)
			admin.POST("/user/change", adminController.ChangeUser)
			admin.DELETE("/users/delete", adminController.DeleteUsers)
		}
	}
}
