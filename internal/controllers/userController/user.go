package userController

import (
	dataBase "backend_v1/internal/dataBase/models"
	"backend_v1/internal/errorCodes"
	"backend_v1/internal/middlewares/auth"
	"backend_v1/internal/middlewares/handlers"
	"backend_v1/models"
	"backend_v1/pkg/utils"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

// @Summary Get user info
// @Description Endpoint to get user info
// @Tags User
// @Accept json
// @Produce json
// @Success 200 array models.UserInfo
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/info [get]
func Info(c *gin.Context) {
	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	email := auth.JwtParse(token).Email
	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	var roles []models.UserRole
	dataBase.DB.Model(models.UserRole{}).Where("id = ?", users[0].ID).Find(&roles)

	c.JSON(http.StatusOK, models.UserInfo{
		Role: roles[0].Role,
		User: users[0],
	})
}

// @Summary Change user password
// @Description Endpoint to change user password
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.ChangePassword true "request body"
// @Success 200 array models.SuccessResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/changepass [post]
func ChangePassword(c *gin.Context) {
	var passwordData models.ChangePassword

	rawData, err := c.GetRawData()

	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Pasing error", errorCodes.ParsingError))
		return
	}
	if err := utils.JsonChecker(passwordData, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &passwordData); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Unmarshal error", errorCodes.ParsingError))
		return
	}

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	email := auth.JwtParse(token).Email
	var users []models.User
	var userPass []models.UserPass
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", users[0].ID).Find(&userPass)

	if len(userPass) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	} else if len(userPass) > 1 {
		panic("duplicate data")
	}
	hashOldPass := utils.Hash(passwordData.OldPassword)
	if userPass[0].Pass != hashOldPass {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Incorrect old password", errorCodes.IncorrectOldPassword))
		return
	}
	digts, symbol := utils.PasswordChecker(passwordData.NewPassword)
	if !digts && !symbol {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Password must be include Digits and Symbols", errorCodes.PasswordShouldByIncludeSymbols))
		return
	}
	hashNewPass := utils.Hash(passwordData.NewPassword)
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", users[0].ID).Update("pass", hashNewPass)

	c.JSON(http.StatusOK, handlers.ErrMsg(true, "Password updated", 0))
}

// @Summary Change user data
// @Description Endpoint to change user data
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.ChangeUserInfo true "request body"
// @Success 200 array models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change [patch]
func ChangeOwnData(c *gin.Context) {
	var user models.ChangeUserInfo

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Unmarshal error", errorCodes.ParsingError))
		return
	}

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	email := auth.JwtParse(token).Email

	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	if user.Login != "" {
		if ok := utils.ValidateLogin(user.Login); !ok {
			c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Login must be include only letters and digits not more 32", errorCodes.IncorrectLogin))
			return
		}
	}

	if len(user.Name) > 32 || len(user.Surname) > 32 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Name and Surname must be not more 32", errorCodes.IncorrectInfoData))
		return
	}

	newData := models.User{
		Login:   handlers.IfEmpty(user.Login, users[0].Login),
		Name:    handlers.IfEmpty(user.Name, users[0].Name),
		Surname: handlers.IfEmpty(user.Surname, users[0].Surname),
		Phone:   handlers.IfEmpty(user.Phone, users[0].Phone),
		Active:  users[0].Active,
		Email:   users[0].Email,
		Created: users[0].Created,
		Updated: dataBase.TimeNow(),
	}

	dataBase.DB.Model(models.User{}).Where("email = ?", email).Updates(newData)

	c.JSON(http.StatusOK, handlers.ErrMsg(true, "User data updated", 0))

}
