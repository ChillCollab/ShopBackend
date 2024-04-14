package adminController

import (
	dataBase "backend_v1/internal/dataBase/models"
	"backend_v1/internal/errorCodes"
	"backend_v1/internal/middlewares/auth"
	"backend_v1/internal/middlewares/handlers"
	"backend_v1/models"
	"backend_v1/pkg/utils"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func ifEmpty(value string, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// @Summary Get all users
// @Description Endpoint to get all users
// @Tags Admin
// @Accept json
// @Produce json
// @Success 200 array models.User
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Router /admin/users [get]
func Users(c *gin.Context) {
	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	var users []models.User
	dataBase.DB.Model(models.User{}).Find(&users)

	c.JSON(http.StatusOK, users)
}

// @Summary Change user data
// @Description Endpoint to change user data. Request must be include "id"
// @Tags Admin
// @Accept json
// @Produce json
// @Param body body models.ChangeUser true "request body"
// @Success 200 array models.SuccessResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Router /admin/user/change [post]
func ChangeUser(c *gin.Context) {
	var user models.ChangeUser
	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Request must be include 'id'", errorCodes.UserNotFound))
		return
	}

	var foundUser []models.User
	dataBase.DB.Model(&models.User{}).Where("id = ?", user.ID).Find(&foundUser)
	if len(foundUser) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "User not found", errorCodes.UserNotFound))
		return
	}

	email := ifEmpty(user.Email, foundUser[0].Email)
	if valid := utils.MailValidator(email); !valid {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Invalid email format", errorCodes.IncorrectEmail))
		return
	}

	newData := models.User{
		Login:   ifEmpty(user.Login, foundUser[0].Login),
		Name:    ifEmpty(user.Name, foundUser[0].Name),
		Surname: ifEmpty(user.Surname, foundUser[0].Surname),
		Email:   email,
		Active:  user.Active,
	}

	if !user.Active {
		dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", user.ID).Delete(models.AccessToken{})
	}

	dataBase.DB.Model(&models.User{}).Where("id = ?", user.ID).UpdateColumns(newData).Update("active", newData.Active)

	c.JSON(http.StatusOK, handlers.ErrMsg(true, "Account updated", 0))
}

// @Summary Delete user account
// @Description Endpoint to delete user account
// @Tags Admin
// @Accept json
// @Produce json
// @Param body body models.UsersArray true "request body"
// @Success 200 array models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Router /admin/users/delete [delete]
func DeleteUsers(c *gin.Context) {
	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	if !auth.CheckAdmin(token) {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}

	var usersArray models.UsersArray

	if err := utils.JsonChecker(usersArray, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorCodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &usersArray); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}

	if len(usersArray.ID) <= 0 {
		c.JSON(http.StatusOK, handlers.ErrMsg(true, "Users deleted", 0))
		return
	}

	idsString := make([]string, len(usersArray.ID))
	for i, id := range usersArray.ID {
		idsString[i] = strconv.Itoa(id)
	}

	result := dataBase.DB.Model(models.User{}).Where("id IN ?", usersArray.ID).Delete(models.User{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusOK, handlers.ErrMsg(false, "No users were found with the provided IDs", errorCodes.UsersNotFound))
		return
	}
	c.JSON(http.StatusOK, handlers.ErrMsg(true, "Users "+strings.Join(idsString, ", ")+" deleted", 0))
}
