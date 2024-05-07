package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"backend/internal/api/middlewares/auth"
	"backend/internal/api/middlewares/images"
	userMiddlewares "backend/internal/api/middlewares/user"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/pkg/utils"

	"github.com/gin-gonic/gin"
)

// Users Получения списка пользователей
// @Summary Get all users
// @Description Endpoint to get all users
// @Tags Admin
// @Accept json
// @Produce json
// @Success 200 array models.User
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/users/list [get]
func (a *App) Users(c *gin.Context) {
	lang := language.LangValue(c)
	token := auth.CheckAuth(c, true, a.db.DB)
	if token == "" {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	if !auth.CheckAdmin(token) {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	var users []models.User
	result := a.db.Model(models.User{}).Find(&users)
	if result.Error != nil {
		a.logger.Logger.Errorf("error get users: %v", result.Error)
		c.JSON(
			http.StatusInternalServerError,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	for i := range users {
		if users[i].AvatarId != "" {
			users[i].AvatarId = images.AvatarUrl(users[i].AvatarId)
		}
	}

	c.JSON(http.StatusOK, users)
}

// ChangeUser изменение пользователя
// @Summary Change user data
// @Description Endpoint to change user data. Request must be include "id"
// @Tags Admin
// @Accept json
// @Produce json
// @Param body body models.ChangeUser true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/users/change [post]
func (a *App) ChangeUser(c *gin.Context) {
	lang := language.LangValue(c)
	var user models.ChangeUser
	token := auth.CheckAuth(c, true, a.db.DB)
	if token == "" {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	if !auth.CheckAdmin(token) {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError),
		)
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		a.logger.Errorf("error unmarshal changeuser: %v", err)
		c.JSON(
			http.StatusBadRequest,
			models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError),
		)
		return
	}

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "must_be_include_id"), errorCodes.UserNotFound))
		return
	}

	if len(user.Name) > 32 || len(user.Surname) > 32 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "name_surname_long"), errorCodes.IncorrectInfoData))
		return
	}

	if user.Phone != "" {
		if valid := utils.PhoneNumberValidator(user.Phone); !valid {
			c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "invalid_phone_number_format"), errorCodes.IncorrectUserPhone))
			return
		}
	}

	if user.Login != "" {
		if valid := utils.ValidateLogin(user.Login); !valid {
			c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "login_can_be_include_letters_digits"), errorCodes.IncorrectUserLogin))
			return
		}
	}

	var foundUser models.User
	result := a.db.Model(&models.User{}).Where("id = ?", user.ID).Find(&foundUser)
	if result.Error != nil {
		a.logger.Errorf("error find user: %v", err)
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UserNotFound))
		return
	}

	email := utils.IfEmpty(user.Email, foundUser.Email)
	if valid := utils.MailValidator(email); !valid {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email"), errorCodes.IncorrectEmail))
		return
	}

	foundUser.Login = utils.IfEmpty(user.Login, foundUser.Login)
	foundUser.Name = utils.IfEmpty(user.Name, foundUser.Name)
	foundUser.Surname = utils.IfEmpty(user.Surname, foundUser.Surname)
	foundUser.Phone = utils.IfEmpty(user.Phone, foundUser.Phone)
	foundUser.Email = email

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
			c.JSON(
				http.StatusBadRequest,
				models.ResponseMsg(false, language.Language(lang, "undefined_user_role"), errorCodes.UndefinedUserRole),
			)
			return
		}

		// Не понял зачем роли искать
		result = a.db.Model(models.UserRole{}).Where("id = ?", foundUser.ID).Find(&foundRole)
		if result.Error != nil {
			a.logger.Errorf("error get user roles: %v", err)
			c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, "internal error", errorCodes.DBError))
			return
		}

		if len(foundRole) > 1 {
			c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
			return
		}

		if len(foundRole) < 1 {
			c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
			return
		}
	}

	//dataBase.DB.Model(&models.User{}).Where("id = ?", user.ID).UpdateColumns(newData).Update("active", newData.Active)
	err = a.db.Save(foundUser).Error
	if err != nil {
		a.logger.Errorf("error update user: %v", err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, "internal error", errorCodes.DBError))
		return
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "user_updated"), 0))
}

// DeleteUsers удаление пользователя
// @Summary Delete user account
// @Description Endpoint to delete user account
// @Tags Admin
// @Accept json
// @Produce json
// @Param body body models.UsersArray true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/users/delete [delete]
func (a *App) DeleteUsers(c *gin.Context) {
	lang := language.LangValue(c)
	token := auth.CheckAuth(c, true, a.db.DB)
	if token == "" {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	if !auth.CheckAdmin(token) {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	var usersArray models.UsersArray
	if err := json.Unmarshal(rawData, &usersArray); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	if len(usersArray.ID) <= 0 {
		c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "user_deleted"), 0))
		return
	}

	idsString := make([]string, len(usersArray.ID))
	for i, id := range usersArray.ID {
		idsString[i] = strconv.Itoa(id)
	}

	result := a.db.Model(models.User{}).Where("id IN ?", usersArray.ID).Delete(models.User{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusOK, models.ResponseMsg(false, language.Language(lang, "users_not_found_by_id"), errorCodes.UsersNotFound))
		return
	}

	c.JSON(
		http.StatusOK,
		models.ResponseMsg(
			true,
			language.Language(lang, "users")+" "+strings.Join(idsString, ", ")+" "+language.Language(lang, "deleted"),
			0,
		),
	)
}
