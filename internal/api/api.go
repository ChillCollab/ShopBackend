package api

import (
	"fmt"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"

	"backend/internal/dataBase"
	"backend/pkg/logger"

	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type App struct {
	server *gin.Engine
	db     *dataBase.Database
	logger logger.Logger
}

func New(server *gin.Engine, dataBase *dataBase.Database, logger logger.Logger) (*App, error) {
	app := &App{
		server: server,
		db:     dataBase,
		logger: logger,
	}

	//Хуевый путь. Ты когда закомпилишь бинерник, .env хуй найдешь.
	err := godotenv.Load("../.env")
	if err != nil {
		return nil, fmt.Errorf("env can't be loaded: %v", err)
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
			auth.POST("/activate/send", a.Send) // domen email
			auth.POST("/activate", a.Activate)
			auth.POST("/logout", a.Logout)
			auth.POST("/recovery", a.Recovery) // domen email
			auth.POST("/recovery/submit", a.RecoverySubmit)
			auth.POST("/register/check", a.CheckRegistrationCode)
		}
		user := route.Group("/user")
		{
			user.GET("/info", a.Info)
			user.POST("/changepass", a.ChangePassword)
			user.PATCH("/change", a.ChangeOwnData)
			user.POST("/change/email", a.ChangeEmail) // domen email
			user.PATCH("/change/email/submit", a.ChangeEmailComplete)
			user.GET("/avatar/:uuid", a.GetAvatar)
			upload := user.Group("/upload")
			{
				upload.POST("/avatar", a.UploadAvatar)
			}
		}

		admin := route.Group("/admin")
		{
			users := admin.Group("/users")
			{
				users.GET("/list", a.Users)
				users.POST("/change", a.ChangeUser)
				users.DELETE("/delete", a.DeleteUsers)
			}
			categories := admin.Group("/categories")
			{
				categories.POST("/create", a.CreateCategory)
				categories.GET("/info", a.CategoryInfoById)
				categories.GET("/list", a.GetCategoryList)
				categories.PATCH("/update", a.CategoryUpdate)
				categories.DELETE("/delete", a.DeleteCategory)
			}
		}
	}
}
