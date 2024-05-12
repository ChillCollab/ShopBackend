package api

import (
	"backend/internal/api/middlewares"
	"fmt"
	"os"

	"backend/internal/dataBase"
	"backend/pkg/broker"
	"backend/pkg/logger"
	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type App struct {
	server *gin.Engine
	db     *dataBase.Database
	logger logger.Logger
	broker *broker.Client
}

func New(server *gin.Engine, dataBase *dataBase.Database, logger logger.Logger) (*App, error) {

	client, errInit := broker.RedisInit()
	if errInit != nil {
		return nil, fmt.Errorf("broker was not connected: %v", errInit)
	}
	logger.Info("Redis connected!")

	app := &App{
		server: server,
		db:     dataBase,
		logger: logger,
		broker: client,
	}

	app.logger.Info("Env loaded")

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:5173/admin"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Authorization", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Access-Control-Allow-Origin"}

	app.server.Use(cors.New(config))
	app.routes()

	return app, nil
}

func (a *App) Run() error {
	return a.server.Run(":" + os.Getenv("APP_PORT"))
}

func (a *App) routes() {
	client := middlewares.Broker{a.broker}
	a.server.GET("/swagger/*any",
		ginSwagger.WrapHandler(swaggerfiles.Handler,
			ginSwagger.DefaultModelsExpandDepth(1),
			ginSwagger.PersistAuthorization(true),
		),
	)
	route := a.server.Group("/api_v1")
	{
		auth := route.Group("/auth")
		{
			auth.POST("/login", a.Login)
			auth.POST("/refresh", client.IsAuthorized, middlewares.IsAdmin, a.Refresh)
			auth.POST("/register", a.Register)
			auth.POST("/activate/send", a.Send) // domen email
			auth.POST("/activate", a.Activate)
			auth.POST("/logout", a.Logout)
			auth.POST("/recovery", a.Recovery) // domen email
			auth.POST("/recovery/submit", a.RecoverySubmit)
			auth.POST("/register/check", a.CheckRegistrationCode)
		}
		user := route.Group("/user")
		{
			user.GET("/info", client.IsAuthorized, a.Info)
			user.POST("/changepass", client.IsAuthorized, a.ChangePassword)
			user.PATCH("/change", client.IsAuthorized, a.ChangeOwnData)
			user.POST("/change/email", client.IsAuthorized, a.ChangeEmail) // domen email
			user.PATCH("/change/email/submit", client.IsAuthorized, a.ChangeEmailComplete)
			user.GET("/avatar/:uuid", client.IsAuthorized, a.GetAvatar)
			upload := user.Group("/upload")
			{
				upload.POST("/avatar", client.IsAuthorized, a.UploadAvatar)
			}
		}

		admin := route.Group("/admin")
		{
			users := admin.Group("/users")
			{
				users.GET("/list", client.IsAuthorized, a.Users)
				users.POST("/change", client.IsAuthorized, a.ChangeUser)
				users.DELETE("/delete", client.IsAuthorized, a.DeleteUsers)
			}
			categories := admin.Group("/categories")
			{
				categories.POST("/create", client.IsAuthorized, a.CreateCategory)
				categories.GET("/info", client.IsAuthorized, a.CategoryInfoById)
				categories.GET("/list", client.IsAuthorized, a.GetCategoryList)
				categories.PATCH("/update", client.IsAuthorized, a.CategoryUpdate)
				categories.DELETE("/delete", client.IsAuthorized, a.DeleteCategory)
			}
		}
	}
}
