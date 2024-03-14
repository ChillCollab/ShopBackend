package userController

import (
	dataBase "backend_v1/internal/dataBase/models"
	"backend_v1/internal/errorCodes"
	"backend_v1/internal/middlewares/auth"
	"backend_v1/internal/middlewares/handlers"
	"backend_v1/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Info(c *gin.Context) {
	token := auth.CheckAuth(c)
	if token == "" {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	email := auth.JwtParse(token).Email
	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)

	c.JSON(http.StatusOK, users[0])
}

func ChangePassword(c *gin.Context) {
	token := auth.CheckAuth(c)
	if token == "" {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	email := auth.JwtParse(token).Email
	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
}
