package api

import (
	"backend/internal/dataBase"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/models/requestData"
	"backend/models/responses"
	"backend/pkg/authorization"
	"backend/pkg/images"
	"backend/pkg/utils"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Info получить информацию пользователя
// @Summary Get user info
// @Description Endpoint to get user info
// @Tags User
// @Accept json
// @Produce json
// @Success 200 array responses.UserInfo
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/info [get]
func (a *App) Info(c *gin.Context) {
	lang := language.LangValue(c)

	token := authorization.GetToken(c)
	parsedToken := authorization.JwtParse(token)

	// Get full user info

	userInfo, err := a.db.UserInfo(parsedToken.Email, parsedToken.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "internal_error"), errorCodes.DBError))
		return
	}

	// Set avatar url
	var url string
	if userInfo.AvatarId != "" {
		url = images.AvatarUrl(userInfo.AvatarId)
	}

	userInfo.AvatarId = url

	// Response
	c.JSON(http.StatusOK, responses.UserInfo{
		Login:    userInfo.Login,
		Name:     userInfo.Name,
		Surname:  userInfo.Surname,
		Phone:    userInfo.Phone,
		AvatarId: url,
		Email:    userInfo.Email,
		Role:     userInfo.RoleId,
		Created:  userInfo.Created,
		Updated:  userInfo.Updated,
	})
}

// ChangePassword изменить пароль
// @Summary Change user password
// @Description Endpoint to change user password
// @Tags User
// @Accept json
// @Produce json
// @Param body body requestData.ChangePassword true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/changepass [post]
func (a *App) ChangePassword(c *gin.Context) {
	lang := language.LangValue(c)

	var passwordData requestData.ChangePassword

	if err := c.ShouldBindJSON(&passwordData); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	token := authorization.GetToken(c)
	parsedToken := authorization.JwtParse(token)

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
			models.ResponseMsg(false, language.Language(lang, "incorrect_old_password"), errorCodes.IncorrectOldPassword),
		)
		return
	}

	digts, symbol := utils.PasswordChecker(passwordData.NewPassword)
	if !digts && !symbol {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "password_should_by_include_symbols"), errorCodes.PasswordShouldByIncludeSymbols))
		return
	}
	hashNewPass := utils.Hash(passwordData.NewPassword)

	err = a.db.Model(models.User{}).Where("id = ?", fullUserInfo.ID).Update("pass", hashNewPass).Error
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
// @Param body body requestData.ChangeUserInfo true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change [patch]
func (a *App) ChangeOwnData(c *gin.Context) {
	lang := language.LangValue(c)
	var user requestData.ChangeUserInfo

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.ParsingError))
		return
	}

	token := authorization.GetToken(c)
	if token == "" {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	email := authorization.JwtParse(token).Email

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
// @Param body body requestData.ChangeEmail true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email [post]
func (a *App) ChangeEmail(c *gin.Context) {
	lang := language.LangValue(c)
	var emailData requestData.ChangeEmail

	if err := c.ShouldBindJSON(&emailData); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	token := authorization.GetToken(c)
	email := authorization.JwtParse(token).Email

	var user models.User

	tx := a.db.Begin()

	if err := tx.Model(models.User{}).Where("email = ?", email).First(&user).Error; err != nil {
		a.logger.Infof("error get user: %v", err)
	}
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UsersNotFound))
		return
	}

	if valid := utils.MailValidator(emailData.Email); !valid {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email"), errorCodes.IncorrectEmail))
		return
	}

	var foundCode models.EmailChange

	if err := a.db.Model(models.EmailChange{}).Where("user_id = ?", user.ID).First(&foundCode).Error; err != nil {
		a.logger.Infof("error get email change code: %v", err)
	}
	if foundCode.Code != 0 {
		if err := tx.Model(models.EmailChange{}).Where("user_id = ?", user.ID).Delete(&foundCode).Error; err != nil {
			tx.Rollback()
			a.logger.Errorf("error delete email change code: %v", err)
		}
	}

	code := utils.GenerateNumberCode()

	if err := tx.Model(&models.User{}).Where("id = ?", user.ID).Update("email", emailData.Email).Error; err != nil {
		tx.Rollback()
		a.logger.Errorf("error update email: %v", err)
	}

	if err := tx.Model(&models.EmailChange{}).Create(&models.EmailChange{
		UserID:  user.ID,
		Email:   emailData.Email,
		Code:    code,
		Created: dataBase.TimeNow(),
	}).Error; err != nil {
		tx.Rollback()
		a.logger.Errorf("error create email change code: %v", err)
	}

	tx.Commit()

	go func() {
		sent := utils.Send(user.Email, "Email change", "Your submit code: "+strconv.Itoa(code), a.db.DB)
		if !sent {
			c.JSON(
				http.StatusInternalServerError,
				models.ResponseMsg(false, language.Language(lang, "email_error"), errorCodes.EmailSendError),
			)
			return
		}
	}()

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "code_was_sent")+user.Email, 0))
}

// ChangeEmailComplete Поздтверждение смены email
// @Summary Change email complete
// @Description Endpoint to complete email change
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.EmailChangeComplete true "request requestData"
// @Success 200 object models.EmailChangeResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email/submit [patch]
func (a *App) ChangeEmailComplete(c *gin.Context) {
	lang := language.LangValue(c)
	var completeBody models.EmailChangeComplete

	if err := c.ShouldBindJSON(&completeBody); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	code := completeBody.Code
	var foundCode models.EmailChange
	if err := a.db.Model(models.EmailChange{}).Where("code = ?", code).First(&foundCode).Error; err != nil {
		a.logger.Infof("error get email change code: %v", err)
	}
	if foundCode.Code == 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "code_not_found"), errorCodes.CodeNotFound))
		return
	}

	var users models.User
	if err := a.db.Model(models.User{}).Where("id = ?", foundCode.UserID).First(&users).Error; err != nil {
		a.logger.Infof("error get user: %v", err)
	}
	if users.ID == 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UsersNotFound))
		return
	}

	a.db.Model(models.User{}).Where("id = ?", foundCode.UserID).Update("email", foundCode.Email)
	a.db.Model(models.User{}).Where("id = ?", foundCode.UserID).Update("updated", dataBase.TimeNow())
	a.db.Model(models.EmailChange{}).Where("code = ?", code).Delete(&foundCode)

	access, refresh, err := authorization.GenerateJWT(authorization.TokenData{
		Authorized: true,
		Email:      foundCode.Email,
		Role:       users.RoleId,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "token_generate_error"), errorCodes.TokenError))
		return
	}

	token := authorization.GetToken(c)
	rejectedToken := models.RejectedToken{
		AccessToken: token,
	}

	if err := a.broker.RedisAddToArray(dataBase.RedisAuthTokens, rejectedToken); err != nil {
		a.logger.Errorf("error add token to redis: %v", err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError))
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
