package api

import (
	"backend/consumer"
	"backend/internal/dataBase"
	errorcodes "backend/internal/errorCodes"
	"backend/internal/roles"
	"backend/models/requestData"
	"backend/models/responses"
	"backend/pkg/authorization"
	"backend/pkg/client"
	"backend/pkg/images"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
// @Param body body requestData.ChangeUser true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/users/change [post]
func (a *App) ChangeUser(c *gin.Context) {
	lang := language.LangValue(c)

	var user requestData.ChangeUser

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
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
	result := a.db.Model(&models.User{}).Where("id = ?", user.ID).First(&foundUser)
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

	if user.Role != 0 {
		found := false
		for _, num := range roles.UserRoles() {
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

	}

	if err := a.db.UpdateUser(user); err != nil {
		a.logger.Errorf("error update user: %v", err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, "internal error", errorCodes.DBError))
		return
	}

	// Response
	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "user_updated"), 0))

	// Attach action
	tokenData := authorization.JwtParse(authorization.GetToken(c))
	fullUserInfo, errInfo := a.db.UserInfo(tokenData.Email, tokenData.Email)
	if errInfo != nil {
		a.logger.Errorf("Error get full user info" + errInfo.Error())
		return
	}

	a.db.AttachAction(models.ActionLogs{
		Action:  "Update user: " + user.Login,
		Login:   fullUserInfo.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})
}

// DeleteUsers удаление пользователя
// @Summary Delete user account
// @Description Endpoint to delete user account
// @Tags Admin
// @Accept json
// @Produce json
// @Param body body requestData.UsersArray true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/users/delete [delete]
func (a *App) DeleteUsers(c *gin.Context) {
	lang := language.LangValue(c)

	var usersArray requestData.UsersArray
	token := authorization.GetToken(c)
	tokenData := authorization.JwtParse(token)

	user, errInfo := a.db.UserInfo(tokenData.Email, tokenData.Email)
	if errInfo != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	err := c.ShouldBindJSON(&usersArray)
	if err != nil {
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

	// Get users by id
	var users []models.User
	found := a.db.Model(&models.User{}).Where("id IN ?", usersArray.ID).Find(&users).Error
	if found != nil {
		a.logger.Errorf("error find users: %v", err)
		return
	}

	var userLogins []string
	for _, usrData := range users {
		userLogins = append(userLogins, usrData.Login)
	}

	if len(users) == 0 {
		c.JSON(http.StatusOK, models.ResponseMsg(false, language.Language(lang, "users_not_found_by_id"), errorCodes.UsersNotFound))
		return
	}

	for _, usr := range users {
		image := usr.AvatarId
		if image != "" {
			var file models.File
			found := a.db.Model(&models.File{}).Where("uuid = ?", image).First(&file).Error
			if found != nil {
				a.logger.Errorf("error find avatar: %v", err)
			}
			oldFilePath := filepath.Join(os.Getenv("IMAGES_PATH"), file.Filename)
			err = os.Remove(oldFilePath)
			if err != nil {
				a.logger.Errorf("error create avatar: %v", err)
			}
			err := a.db.Model(&models.File{}).Where("uuid = ?", usr.AvatarId).Delete(&models.File{})
			if err.Error != nil {
				a.logger.Errorf("error delete avatar: %v", err.Error)
			}
		}
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

	a.db.AttachAction(models.ActionLogs{
		Action:  "Delete users " + strings.Join(userLogins, ", "),
		Login:   user.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})
}

// CreateUser создание пользователя
// @Summary Create user account
// @Description Endpoint to create user account
// @Tags Admin
// @Accept json
// @Produce json
// @Param body body requestData.CreateUser true "request requestData"
// @Success 200 object responses.CreateUserAdmin
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/users/create [post]
func (a *App) CreateUser(c *gin.Context) {
	lang := language.LangValue(c)
	var userData requestData.CreateUser
	err := c.ShouldBindJSON(&userData)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	if userData.Login == "" || userData.Name == "" || userData.Surname == "" || userData.Email == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_data_create_user"), errorCodes.IncorrectDataCreateUser))
		return
	}

	if !utils.MailValidator(userData.Email) {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email"), errorCodes.IncorrectEmail))
		return
	}

	if a.db.CheckIfUserExist(userData.Login, userData.Email) {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_already_exist"), errorCodes.UserAlreadyExist))
		return
	}

	// Create user
	if err := a.db.CreateUser(models.User{
		Login:   userData.Login,
		Name:    userData.Name,
		Surname: userData.Surname,
		Email:   userData.Email,
		Active:  true,
		Role:    0,
		Created: dataBase.TimeNow(),
		Updated: dataBase.TimeNow(),
	}); err != nil {
		a.logger.Errorf("error create user: %v", err)
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "create_user_error"), errorCodes.CreateUserError))
		return
	}

	var createdUser models.User
	if foundErr := a.db.Model(models.User{}).Where("login = ?", userData.Login).First(&createdUser).Error; foundErr != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "create_user_error"), errorCodes.CreateUserError))
		return
	}

	if userData.SendMail {
		go func() {
			code, errGen := utils.CodeGen()
			if errGen != nil {
				a.logger.Errorf("error generate code: %v", errGen)
				c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "error"), errorcodes.ServerError))
				return
			}
			create := a.db.Model(&models.RegToken{}).Create(models.RegToken{
				UserId:  int(createdUser.ID),
				Type:    0,
				Code:    code,
				Created: dataBase.TimeNow(),
			})
			if create.Error != nil {
				a.logger.Error("Create mail in table error: " + create.Error.Error())
				return
			}

			if !consumer.SendRegisterMail(createdUser.Email, lang, createdUser, code, a.db.DB) {
				a.logger.Error("Email send error to address: " + createdUser.Email)
				return
			}
		}()
	}

	c.JSON(http.StatusOK, responses.CreateUserAdmin{
		Message: language.Language(lang, "user_created"),
		Success: true,
		User: responses.UserInfo{
			Login:    createdUser.Login,
			Name:     createdUser.Name,
			Surname:  createdUser.Surname,
			Email:    createdUser.Email,
			AvatarId: createdUser.AvatarId,
			Phone:    createdUser.Phone,
			Role:     createdUser.Role,
			Created:  createdUser.Created,
			Updated:  createdUser.Updated,
		},
	})
}
