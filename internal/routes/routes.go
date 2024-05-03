package routes

import (
	"backend/internal/controllers/adminController"
	"backend/internal/controllers/authController"
	"backend/internal/controllers/categoriesController"
	"backend/internal/controllers/userController"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-gonic/gin"
)

func Routes(r *gin.Engine) {
	r.GET("/swagger/*any",
		ginSwagger.WrapHandler(swaggerfiles.Handler,
			ginSwagger.DefaultModelsExpandDepth(1),
			ginSwagger.PersistAuthorization(true),
		),
	)
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
			user.GET("/avatar/:uuid", userController.GetAvatar)
			upload := user.Group("/upload")
			{
				upload.POST("/avatar", userController.UploadAvatar)
			}
		}

		admin := api.Group("/admin")
		{
			users := admin.Group("/users")
			{
				users.GET("/list", adminController.Users)
				users.POST("/change", adminController.ChangeUser)
				users.DELETE("/delete", adminController.DeleteUsers)
			}
			categories := admin.Group("/categories")
			{
				categories.POST("/create", categoriesController.CreateCategory)
				categories.GET("/info", categoriesController.CategoryInfoById)
				categories.GET("/list", categoriesController.GetCategoryList)
				categories.PATCH("/update", categoriesController.CategoryUpdate)
				categories.DELETE("/delete", categoriesController.DeleteCategory)
			}
		}
	}
}
