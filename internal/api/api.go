package api

import (
	server "backend/internal"
	"backend/internal/controllers"
	"backend/pkg/logger"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-gonic/gin"
)

type Api struct {
	srv    *gin.Engine
	logger logger.Logger
}

func New(srv *server.App) Api {
	return Api{
		srv:    srv.Server,
		logger: srv.Logger,
	}
}

func (a Api) Routes(r *gin.Engine) {

	r.GET("/swagger/*any",
		ginSwagger.WrapHandler(swaggerfiles.Handler,
			ginSwagger.DefaultModelsExpandDepth(1),
			ginSwagger.PersistAuthorization(true),
		),
	)
	route := r.Group("/api_v1")
	{
		auth := route.Group("/auth")
		{
			auth.POST("/login", controllers.Login)
			auth.POST("/refresh", controllers.Refresh)
			auth.POST("/register", controllers.Register)
			auth.POST("/activate/send", controllers.Send) // domen email
			auth.POST("/activate", controllers.Activate)
			auth.POST("/logout", controllers.Logout)
			auth.POST("/recovery", controllers.Recovery) // domen email
			auth.POST("/recovery/submit", controllers.RecoverySubmit)
			auth.POST("/register/check", controllers.CheckRegistrationCode)
		}
		user := route.Group("/user")
		{
			user.GET("/info", controllers.Info)
			user.POST("/changepass", controllers.ChangePassword)
			user.PATCH("/change", controllers.ChangeOwnData)
			user.POST("/change/email", controllers.ChangeEmail) // domen email
			user.PATCH("/change/email/submit", controllers.ChangeEmailComplete)
			user.GET("/avatar/:uuid", controllers.GetAvatar)
			upload := user.Group("/upload")
			{
				upload.POST("/avatar", controllers.UploadAvatar)
			}
		}

		admin := route.Group("/admin")
		{
			users := admin.Group("/users")
			{
				users.GET("/list", controllers.Users)
				users.POST("/change", controllers.ChangeUser)
				users.DELETE("/delete", controllers.DeleteUsers)
			}
			categories := admin.Group("/categories")
			{
				categories.POST("/create", controllers.CreateCategory)
				categories.GET("/info", controllers.CategoryInfoById)
				categories.GET("/list", controllers.GetCategoryList)
				categories.PATCH("/update", controllers.CategoryUpdate)
				categories.DELETE("/delete", controllers.DeleteCategory)
			}
		}
	}
}
