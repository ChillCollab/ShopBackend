package api

import (
	"backend/internal/api/middlewares"
	"backend/models/body"
	"backend/models/responses"
	"encoding/json"
	"net/http"
	"strconv"

	"backend/internal/api/middlewares/images"
	"backend/internal/dataBase"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/pkg/utils"

	"github.com/gin-gonic/gin"
)

// Info получить информацию пользователя
// @Summary Get user info
// @Description Endpoint to get user info
// @Tags User
// @Accept json
// @Produce json
// @Success 200 array responses.UserInfo
// @Failure 401 object models.ResponseMsg
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/info [get]
func (a *App) Info(c *gin.Context) {
	lang := language.LangValue(c)

	token := middlewares.GetToken(c)
	parsedToken := middlewares.JwtParse(token)

	// Get full user info
	var users models.User
	userInfo, err := a.db.UserInfo(parsedToken.Email, parsedToken.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "internal_error"), errorCodes.DBError))
		return
	}

	// Set avatar url
	var url string
	if users.AvatarId != "" {
		url = images.AvatarUrl(users.AvatarId)
	}

	users.AvatarId = url

	// Response
	c.JSON(http.StatusOK, responses.UserInfo{
		Login:   userInfo.Name,
		Name:    userInfo.Name,
		Surname: userInfo.Surname,
		Phone:   userInfo.Phone,
		Email:   userInfo.Email,
		Role:    userInfo.RoleId,
		Created: userInfo.Created,
		Updated: userInfo.Updated,
	})
}

// ChangePassword изменить пароль
// @Summary Change user password
// @Description Endpoint to change user password
// @Tags User
// @Accept json
// @Produce json
// @Param body body body.ChangePassword true "request body"
// @Success 200 object models.ResponseMsg
// @Failure 401 object models.ResponseMsg
// @Failure 403 object models.ResponseMsg
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/changepass [post]
func (a *App) ChangePassword(c *gin.Context) {
	lang := language.LangValue(c)

	var passwordData body.ChangePassword

	if err := c.ShouldBindJSON(&passwordData); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	token := middlewares.GetToken(c)
	parsedToken := middlewares.JwtParse(token)

	fullUserInfo, err := a.db.UserInfo(parsedToken.Email, parsedToken.Email)
	if err != nil {
		a.logger.Errorf("error get user info: %v", err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "internal_error"), errorCodes.DBError))
		return
	}

	hashOldPass := utils.Hash(passwordData.OldPassword)
	if fullUserInfo.Pass != hashOldPass {
		c.JSON(
			http.StatusBadRequest,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.IncorrectOldPassword),
		)
		return
	}

	digts, symbol := utils.PasswordChecker(passwordData.NewPassword)
	if !digts && !symbol {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "password_should_by_include_symbols"), errorCodes.PasswordShouldByIncludeSymbols))
		return
	}
	hashNewPass := utils.Hash(passwordData.NewPassword)

	err = a.db.Model(models.User{}).Where("user_id = ?", fullUserInfo.ID).Update("pass", hashNewPass).Error
	if err != nil {
		a.logger.Errorf("error update password user: %v", err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, "internal error", errorCodes.DBError))
		return
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "password_updated"), 0))
}

// ChangeOwnData изменить данные пользователя
// @Summary Change user data
// @Description Endpoint to change user data
// @Tags User
// @Accept json
// @Produce json
// @Param body body body.ChangeUserInfo true "request body"
// @Success 200 object models.ResponseMsg
// @Failure 400 object models.ResponseMsg
// @Failure 401 object models.ResponseMsg
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change [patch]
func (a *App) ChangeOwnData(c *gin.Context) {
	lang := language.LangValue(c)
	var user body.ChangeUserInfo

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.ParsingError))
		return
	}

	token := middlewares.GetToken(c)
	if token == "" {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	email := middlewares.JwtParse(token).Email

	var users []models.User
	a.db.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) <= 0 {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	if user.Login != "" {
		if ok := utils.ValidateLogin(user.Login); !ok {
			c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "login_can_be_include_letters_digits"), errorCodes.IncorrectLogin))
			return
		}
	}

	if len(user.Name) > 32 || len(user.Surname) > 32 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "name_surname_long"), errorCodes.IncorrectInfoData))
		return
	}

	if user.Login != "" {
		var checkLogin []models.User
		a.db.Model(models.User{}).Where("login = ?", user.Login).Where("id != ?", users[0].ID).Find(&checkLogin)
		if len(checkLogin) > 0 {
			c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "login_already_exist"), errorCodes.LoginAlreadyExist))
			return
		}
	}

	newData := models.User{
		Login:   utils.IfEmpty(user.Login, users[0].Login),
		Name:    utils.IfEmpty(user.Name, users[0].Name),
		Surname: utils.IfEmpty(user.Surname, users[0].Surname),
		Phone:   utils.IfEmpty(user.Phone, users[0].Phone),
		Active:  users[0].Active,
		Email:   users[0].Email,
		Created: users[0].Created,
		Updated: dataBase.TimeNow(),
	}

	a.db.Model(models.User{}).Where("email = ?", email).Updates(newData)

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "user_data_updated"), 0))

}

// ChangeEmail изменить email пользователя
// @Summary Change user email
// @Description Endpoint to change user email
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.EmailChangeRequest true "request body"
// @Success 200 object models.ResponseMsg
// @Failure 400 object models.ResponseMsg
// @Failure 401 object models.ResponseMsg
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email [post]
func (a *App) ChangeEmail(c *gin.Context) {
	lang := language.LangValue(c)
	var emailData models.EmailChangeRequest

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &emailData); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.ParsingError))
		return
	}
	token := middlewares.GetToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	email := middlewares.JwtParse(token).Email

	var users []models.User

	a.db.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UsersNotFound))
		return
	}

	if len(users) > 1 {
		//сука
		panic("duplicate data")
	}

	if valid := utils.MailValidator(emailData.Email); !valid {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email"), errorCodes.IncorrectEmail))
		return
	}

	var foundCode []models.EmailChange

	a.db.Model(models.EmailChange{}).Where("user_id = ?", users[0].ID).Find(&foundCode)
	if len(foundCode) > 0 || len(foundCode) > 1 {
		a.db.Model(models.EmailChange{}).Where("user_id = ?", users[0].ID).Delete(&foundCode)
	}

	code := utils.GenerateNumberCode()
	sent := utils.Send(users[0].Email, "Email change", "Your submit code: "+strconv.Itoa(code), a.db.DB)
	if !sent {
		c.JSON(
			http.StatusInternalServerError,
			models.ResponseMsg(false, language.Language(lang, "email_error"), errorCodes.EmailSendError),
		)
		return
	}

	// Ты должен использовать .Save
	newEmail := models.EmailChange{
		UserID:  users[0].ID,
		Email:   emailData.Email,
		Code:    code,
		Created: dataBase.TimeNow(),
	}
	a.db.Model(models.EmailChange{}).Create(&newEmail)

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "code_was_sent")+users[0].Email, 0))
}

// ChangeEmailComplete Поздтверждение смены email
// @Summary Change email complete
// @Description Endpoint to complete email change
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.EmailChangeComplete true "request body"
// @Success 200 object models.EmailChangeResponse
// @Failure 400 object models.ResponseMsg
// @Failure 401 object models.ResponseMsg
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email/submit [patch]
func (a *App) ChangeEmailComplete(c *gin.Context) {
	lang := language.LangValue(c)
	var completeBody models.EmailChangeComplete

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &completeBody); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.ParsingError))
		return
	}

	token := middlewares.GetToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	code := completeBody.Code
	var foundCode []models.EmailChange
	a.db.Model(models.EmailChange{}).Where("code = ?", code).Find(&foundCode)
	if len(foundCode) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "code_not_found"), errorCodes.CodeNotFound))
		return
	} else if len(foundCode) > 1 {
		panic("duplicate data")
	}

	var users []models.User
	a.db.Model(models.User{}).Where("id = ?", foundCode[0].UserID).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UsersNotFound))
		return
	} else if len(users) > 1 {
		panic("duplicate data")
	}

	var userRole []models.UserRole
	a.db.Model(models.UserRole{}).Where("id = ?", users[0].ID).Find(&userRole)
	if len(userRole) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_role_not_found"), errorCodes.RoleNotFound))
		return
	} else if len(userRole) > 1 {
		panic("duplicate data")
	}

	a.db.Model(models.User{}).Where("id = ?", foundCode[0].UserID).Update("email", foundCode[0].Email)
	a.db.Model(models.User{}).Where("id = ?", foundCode[0].UserID).Update("updated", dataBase.TimeNow())
	a.db.Model(models.EmailChange{}).Where("code = ?", code).Delete(&foundCode)

	access, refresh, err := middlewares.GenerateJWT(middlewares.TokenData{
		Authorized: true,
		Email:      foundCode[0].Email,
		Role:       userRole[0].Role,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "token_generate_error"), errorCodes.TokenError))
		return
	}

	tokens := models.RejectedToken{
		AccessToken:  access,
		RefreshToken: refresh,
	}
	if err := a.db.Model(models.RejectedToken{}).Where("user_id = ?", users[0].ID).Updates(tokens); err.Error != nil {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "token_update_error"), errorCodes.TokenUpdateError))
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
