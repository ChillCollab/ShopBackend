package adminController

import (
	dataBase "backend_v1/internal/dataBase/models"
	"backend_v1/internal/errorCodes"
	"backend_v1/internal/middlewares/auth"
	"backend_v1/internal/middlewares/handlers"
	"backend_v1/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Users(c *gin.Context) {
	token := auth.CheckAuth(c)
	if token == "" {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	var users []models.User
	dataBase.DB.Model(models.User{}).Find(&users)

	c.JSON(http.StatusOK, users)
}
