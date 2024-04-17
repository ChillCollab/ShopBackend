package routes

import (
	"backend/internal/controllers/adminController"
	"backend/internal/controllers/authController"
	"backend/internal/controllers/userController"

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
			auth.POST("/activate/send", authController.Send) // domen email
			auth.POST("/activate", authController.Activate)
			auth.POST("/logout", authController.Logout)
			auth.POST("/recovery", authController.Recovery) // domen email
			auth.POST("/recovery/submit", authController.RecoverySubmit)
			auth.POST("/register/check", authController.CheckRegistrationCode)
		}
		user := api.Group("/user")
		{
			user.GET("/info", userController.Info)
			user.POST("/changepass", userController.ChangePassword)
			user.PATCH("/change", userController.ChangeOwnData)
			user.POST("/change/email", userController.ChangeEmail) // domen email
			user.PATCH("/change/email/submit", userController.ChangeEmailComplete)
		}

		admin := api.Group("/admin")
		{
			admin.GET("/users", adminController.Users)
			admin.POST("/user/change", adminController.ChangeUser)
			admin.DELETE("/users/delete", adminController.DeleteUsers)
		}
	}
}
