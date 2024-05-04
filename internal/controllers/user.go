package controllers

import (
	dataBase "backend/internal/dataBase/models"
	"backend/internal/errorCodes"
	"backend/internal/middlewares/auth"
	"backend/internal/middlewares/handlers"
	"backend/internal/middlewares/images"
	"backend/internal/middlewares/language"
	"backend/models"
	"backend/pkg/utils"
	"encoding/json"
	"net/http"
	"strconv"

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
	lang := language.LangValue(c)
	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	email := auth.JwtParse(token).Email
	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	var roles []models.UserRole
	dataBase.DB.Model(models.UserRole{}).Where("id = ?", users[0].ID).Find(&roles)

	var url string
	if users[0].AvatarId != "" {
		url = images.AvatarUrl(users[0].AvatarId)
	} else {
		url = ""
	}

	users[0].AvatarId = url

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
// @Success 200 object models.SuccessResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/changepass [post]
func ChangePassword(c *gin.Context) {
	lang := language.LangValue(c)
	var passwordData models.ChangePassword

	rawData, err := c.GetRawData()

	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &passwordData); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.ParsingError))
		return
	}

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(401, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	email := auth.JwtParse(token).Email
	var users []models.User
	var userPass []models.UserPass
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", users[0].ID).Find(&userPass)

	if len(userPass) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	} else if len(userPass) > 1 {
		panic("duplicate data")
	}
	hashOldPass := utils.Hash(passwordData.OldPassword)
	if userPass[0].Pass != hashOldPass {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.IncorrectOldPassword))
		return
	}
	digts, symbol := utils.PasswordChecker(passwordData.NewPassword)
	if !digts && !symbol {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "password_should_by_include_symbols"), errorCodes.PasswordShouldByIncludeSymbols))
		return
	}
	hashNewPass := utils.Hash(passwordData.NewPassword)
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", users[0].ID).Update("pass", hashNewPass)

	c.JSON(http.StatusOK, handlers.ErrMsg(true, language.Language(lang, "password_updated"), 0))
}

// @Summary Change user data
// @Description Endpoint to change user data
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.ChangeUserInfo true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change [patch]
func ChangeOwnData(c *gin.Context) {
	lang := language.LangValue(c)
	var user models.ChangeUserInfo

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.ParsingError))
		return
	}

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	email := auth.JwtParse(token).Email

	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	if user.Login != "" {
		if ok := utils.ValidateLogin(user.Login); !ok {
			c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "login_can_be_include_letters_digits"), errorCodes.IncorrectLogin))
			return
		}
	}

	if len(user.Name) > 32 || len(user.Surname) > 32 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "name_surname_long"), errorCodes.IncorrectInfoData))
		return
	}

	if user.Login != "" {
		var checkLogin []models.User
		dataBase.DB.Model(models.User{}).Where("login = ?", user.Login).Where("id != ?", users[0].ID).Find(&checkLogin)
		if len(checkLogin) > 0 {
			c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "login_already_exist"), errorCodes.LoginAlreadyExist))
			return
		}
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

	c.JSON(http.StatusOK, handlers.ErrMsg(true, language.Language(lang, "user_data_updated"), 0))

}

// @Summary Change user email
// @Description Endpoint to change user email
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.EmailChangeRequest true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email [post]
func ChangeEmail(c *gin.Context) {
	lang := language.LangValue(c)
	var emailData models.EmailChangeRequest

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &emailData); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.ParsingError))
		return
	}
	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	email := auth.JwtParse(token).Email

	var users []models.User

	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)

	if len(users) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "user_not_found"), errorCodes.UsersNotFound))
		return
	} else if len(users) > 1 {
		panic("duplicate data")
	}

	if valid := utils.MailValidator(emailData.Email); !valid {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "incorrect_email"), errorCodes.IncorrectEmail))
		return
	}

	var foundCode []models.EmailChange

	dataBase.DB.Model(models.EmailChange{}).Where("user_id = ?", users[0].ID).Find(&foundCode)
	if len(foundCode) > 0 || len(foundCode) > 1 {
		dataBase.DB.Model(models.EmailChange{}).Where("user_id = ?", users[0].ID).Delete(&foundCode)
	}

	code := utils.GenerateNumberCode()
	sent := utils.Send(users[0].Email, "Email change", "Your submit code: "+strconv.Itoa(code), dataBase.DB)
	if !sent {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, language.Language(lang, "email_error"), errorCodes.EmailSendError))
		return
	}
	newEmail := models.EmailChange{
		UserID:  users[0].ID,
		Email:   emailData.Email,
		Code:    code,
		Created: dataBase.TimeNow(),
	}
	dataBase.DB.Model(models.EmailChange{}).Create(&newEmail)

	c.JSON(http.StatusOK, handlers.ErrMsg(true, language.Language(lang, "code_was_sent")+users[0].Email, 0))
}

// @Summary Change email complete
// @Description Endpoint to complete email change
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.EmailChangeComplete true "request body"
// @Success 200 object models.EmailChangeResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email/submit [patch]
func ChangeEmailComplete(c *gin.Context) {
	lang := language.LangValue(c)
	var completeBody models.EmailChangeComplete

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &completeBody); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.ParsingError))
		return
	}

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	code := completeBody.Code
	var foundCode []models.EmailChange
	dataBase.DB.Model(models.EmailChange{}).Where("code = ?", code).Find(&foundCode)
	if len(foundCode) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "code_not_found"), errorCodes.CodeNotFound))
		return
	} else if len(foundCode) > 1 {
		panic("duplicate data")
	}

	var users []models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", foundCode[0].UserID).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "user_not_found"), errorCodes.UsersNotFound))
		return
	} else if len(users) > 1 {
		panic("duplicate data")
	}

	var userRole []models.UserRole
	dataBase.DB.Model(models.UserRole{}).Where("id = ?", users[0].ID).Find(&userRole)
	if len(userRole) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "user_role_not_found"), errorCodes.RoleNotFound))
		return
	} else if len(userRole) > 1 {
		panic("duplicate data")
	}

	dataBase.DB.Model(models.User{}).Where("id = ?", foundCode[0].UserID).Update("email", foundCode[0].Email)
	dataBase.DB.Model(models.User{}).Where("id = ?", foundCode[0].UserID).Update("updated", dataBase.TimeNow())
	dataBase.DB.Model(models.EmailChange{}).Where("code = ?", code).Delete(&foundCode)

	access, refresh, err := auth.GenerateJWT(auth.TokenData{
		Authorized: true,
		Email:      foundCode[0].Email,
		Role:       userRole[0].Role,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, language.Language(lang, "token_generate_error"), errorCodes.TokenError))
		return
	}

	tokens := models.AccessToken{
		UserId:       users[0].ID,
		AccessToken:  access,
		RefreshToken: refresh,
	}
	if err := dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", users[0].ID).Updates(tokens); err.Error != nil {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, language.Language(lang, "token_update_error"), errorCodes.TokenUpdateError))
		return
	}

	response := models.EmailChangeResponse{
		Success:      true,
		Messages:     language.Language(lang, "email_updated"),
		AccessToken:  access,
		RefreshToken: refresh,
	}

	c.JSON(http.StatusOK, response)
}
