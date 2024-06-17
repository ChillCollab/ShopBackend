package api

import (
	"fmt"
	"os"

	"backend/internal/api/middlewares"

	"github.com/gin-contrib/cors"

	"backend/internal/dataBase"
	"backend/pkg/broker"
	"backend/pkg/logger"

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

	if err := dataBase.RedisSyncAuth(client); err != nil {
		return nil, fmt.Errorf("error while syncing redis: %v", err)
	}
	app.logger.Info("Redis synced!")

	go dataBase.RedisUpdateAuth(client)
	app.logger.Info("Redis update started!")

	app.logger.Info("Env loaded")

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:5173/admin", "http://109.71.240.99"}
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
	client := middlewares.Broker{Client: a.broker}
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
			auth.POST("/refresh", a.Refresh)
			auth.POST("/register", a.Register)
			auth.POST("/activate/send", a.Send) // send email
			auth.POST("/activate", a.Activate)
			auth.POST("/logout", client.IsAuthorized, a.Logout)
			auth.POST("/recovery", a.Recovery) // send email
			auth.POST("/recovery/submit", a.RecoverySubmit)
			auth.POST("/register/check", a.CheckRegistrationCode)
			auth.POST("/recovery/check", a.CheckRecoveryCode)
		}
		user := route.Group("/user")
		{
			user.GET("/info", client.IsAuthorized, a.Info)
			user.POST("/changepass", client.IsAuthorized, a.ChangePassword)
			user.PATCH("/change", client.IsAuthorized, a.ChangeOwnData)
			user.POST("/change/email", client.IsAuthorized, a.ChangeEmail) // send email
			user.PATCH("/change/email/submit", client.IsAuthorized, a.ChangeEmailComplete)
			user.GET("/avatar/:uuid", a.GetAvatar)
			upload := user.Group("/upload")
			{
				upload.POST("/avatar", client.IsAuthorized, a.UploadAvatar)
			}
		}

		admin := route.Group("/admin")
		{
			users := admin.Group("/users")
			{
				users.GET("/list", client.IsAuthorized, middlewares.IsAdmin, a.Users)
				users.POST("/change", client.IsAuthorized, middlewares.IsAdmin, a.ChangeUser)
				users.DELETE("/delete", client.IsAuthorized, middlewares.IsAdmin, a.DeleteUsers)
			}
			categories := admin.Group("/categories")
			{
				categories.POST("/create", client.IsAuthorized, middlewares.IsAdmin, a.CreateCategory)
				categories.GET("/info", client.IsAuthorized, middlewares.IsAdmin, a.CategoryInfoById)
				categories.GET("/list", client.IsAuthorized, middlewares.IsAdmin, a.GetCategoryList)
				categories.PATCH("/update", client.IsAuthorized, middlewares.IsAdmin, a.CategoryUpdate)
				categories.DELETE("/delete", client.IsAuthorized, middlewares.IsAdmin, a.DeleteCategory)
			}
			actions := admin.Group("/actions")
			{
				actions.GET("/list", client.IsAuthorized, middlewares.IsAdmin, a.GetActions)
			}
		}
	}
}
