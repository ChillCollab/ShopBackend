package adminController

import (
	dataBase "backend/internal/dataBase/models"
	"backend/internal/errorCodes"
	"backend/internal/middlewares/auth"
	"backend/internal/middlewares/handlers"
	userMiddlewares "backend/internal/middlewares/user"
	"backend/models"
	"backend/pkg/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// @Summary Get all users
// @Description Endpoint to get all users
// @Tags Admin
// @Accept json
// @Produce json
// @Success 200 array models.User
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
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
// @Security ApiKeyAuth
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
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Request must be include 'id'", errorCodes.UserNotFound))
		return
	}

	if len(user.Name) > 32 || len(user.Surname) > 32 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Name and Surname must be not more 32", errorCodes.IncorrectInfoData))
		return
	}

	if user.Phone != "" {
		if valid := utils.PhoneNumberValidator(user.Phone); !valid {
			c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Invalid phone number format", errorCodes.IncorrectUserPhone))
			return
		}

	}
	if user.Login != "" {
		if valid := utils.ValidateLogin(user.Login); !valid {
			c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Invalid login format. Login must be include only one word and symbols not more 32 ", errorCodes.IncorrectUserLogin))
			return
		}
	}

	var foundUser []models.User
	dataBase.DB.Model(&models.User{}).Where("id = ?", user.ID).Find(&foundUser)
	if len(foundUser) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "User not found", errorCodes.UserNotFound))
		return
	}

	email := handlers.IfEmpty(user.Email, foundUser[0].Email)
	if valid := utils.MailValidator(email); !valid {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Invalid email format", errorCodes.IncorrectEmail))
		return
	}

	newData := models.User{
		Login:   handlers.IfEmpty(user.Login, foundUser[0].Login),
		Name:    handlers.IfEmpty(user.Name, foundUser[0].Name),
		Surname: handlers.IfEmpty(user.Surname, foundUser[0].Surname),
		Phone:   handlers.IfEmpty(user.Phone, foundUser[0].Phone),
		Email:   email,
		Active:  foundUser[0].Active,
		Created: foundUser[0].Created,
		Updated: dataBase.TimeNow(),
	}

	var foundRole []models.UserRole

	if user.Role != 0 {
		found := false
		for _, num := range userMiddlewares.UserRoles() {
			if num == user.Role {
				found = true
				break
			}
		}
		if !found {
			c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Undefined user role", errorCodes.UndefinedUserRole))
			return
		}

		dataBase.DB.Model(models.UserRole{}).Where("id = ?", foundUser[0].ID).Find(&foundRole)
		if len(foundUser) > 1 {
			c.JSON(http.StatusForbidden, handlers.ErrMsg(false, "Multiple data", errorCodes.MultipleData))
			return
		} else if len(foundUser) < 1 {
			panic("User role not found")
		}

		dataBase.DB.Model(models.UserRole{}).Where("id = ?", foundUser[0].ID).UpdateColumn("role", user.Role)
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
// @Security ApiKeyAuth
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
