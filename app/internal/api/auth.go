package api

import (
	"backend/pkg/authorization"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"backend/internal/dataBase"
	errorcodes "backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/models/requestData"
	"backend/models/responses"
	utils "backend/pkg/utils"

	"github.com/gin-gonic/gin"
)

// @Summary Login into account
// @Description Endpoint to login into account
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body requestData.Login true "request requestData"
// @Success 200 object responses.AuthResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Router /auth/login [post]

func (a *App) Login(c *gin.Context) {
	var user requestData.Login

	lang := language.LangValue(c)
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError),
		)
		return
	}

	userInfo, err := a.db.UserInfo(user.Login, user.Login)
	if err != nil {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized),
		)
		return
	}

	if !userInfo.Active {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(
				false,
				language.Language(lang, "user")+" "+user.Login+" "+language.Language(lang, "is_not_active"),
				errorcodes.UserIsNotActive,
			),
		)
		return
	}

	userPass := utils.Hash(user.Password)
	if userPass != userInfo.Pass {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized),
		)
		return
	}

	authResponse := responses.AuthResponse{
		User: responses.UserInfo{
			Login:   userInfo.Login,
			Name:    userInfo.Name,
			Surname: userInfo.Surname,
			Email:   userInfo.Email,
			Phone:   userInfo.Phone,
			Role:    userInfo.RoleId,
			Created: userInfo.Created,
			Updated: userInfo.Updated,
		},
	}

	accessToken, refreshToken, err := authorization.GenerateJWT(authorization.TokenData{
		Authorized: true,
		Email:      userInfo.Email,
		Role:       userInfo.RoleId,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	alive, err := authorization.CheckTokenRemaining(accessToken)
	if err != nil {
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	authResponse.AccessToken = accessToken
	authResponse.RefreshToken = refreshToken
	authResponse.Alive = alive

	c.JSON(http.StatusOK, authResponse)
}

// @Summary Register account
// @Description Endpoint to register a new user account
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body requestData.Register true "request requestData"
// @Success 200 object responses.RegisterResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Router /auth/register [post]
func (a *App) Register(c *gin.Context) {
	lang := language.LangValue(c)
	var user requestData.Register
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if user.Name == "" || user.Surname == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_name_or_surname"), errorcodes.NameOfSurnameIncorrect))
		return
	}

	if !utils.MailValidator(user.Email) {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email"), errorcodes.IncorrectEmail))
		return
	}
	if user.Login == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "login_empty"), errorcodes.LoginCanBeEmpty))
		return
	}
	if len(user.Name) > 32 || len(user.Surname) > 32 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "name_surname_long"), errorcodes.IncorrectInfoData))
		return
	}
	if ok := utils.ValidateLogin(user.Login); !ok {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "login_can_be_include_letters_digits"), errorcodes.IncorrectLogin))
		return
	}

	var ifExist []models.User
	var foundLogin []models.User

	a.db.Where("email = ?", user.Email).Find(&ifExist)
	a.db.Model(&models.User{}).Where("login = ?", user.Login).Find(&foundLogin)

	if len(ifExist) > 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_already_exist"), errorcodes.UserAlreadyExist))
		return
	}
	if len(foundLogin) > 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "login_already_exist"), errorcodes.LoginAlreadyExist))
		return
	}

	completeUser := models.User{
		Login:   user.Login,
		Name:    user.Name,
		Surname: user.Surname,
		Email:   user.Email,
		Created: dataBase.TimeNow(),
		Updated: dataBase.TimeNow(),
	}

	errCreate := a.db.CreateUser(completeUser)
	if errCreate != nil {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	c.JSON(http.StatusOK, responses.RegisterResponse{
		Error: false,
		User: responses.UserInfo{
			Login:   completeUser.Login,
			Name:    completeUser.Name,
			Surname: completeUser.Surname,
			Email:   completeUser.Email,
			Role:    0,
			Phone:   completeUser.Phone,
			Created: completeUser.Created,
			Updated: completeUser.Updated,
		},
	})
}

//hi

// @Summary Send register email
// @Description Endpoint to send register email to submit registration
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body requestData.Send true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/activate/send [post]
func (a *App) Send(c *gin.Context) {
	lang := language.LangValue(c)
	var user requestData.Send

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if user.Email == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_registered"), errorcodes.UserNotFound))
		return
	}
	var foundUser models.User
	a.db.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorcodes.UserNotFound))
		return
	}

	var checkUser []models.RegToken

	a.db.Model(&models.RegToken{}).Where("user_id = ? AND type = ?", foundUser.ID, 0).Find(&checkUser)
	if len(checkUser) > 1 {
		del := a.db.Model(&checkUser).Delete(checkUser)
		if del.Error != nil {
			c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
			return
		}
		c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorcodes.MultipleData))
		return
	}
	if len(checkUser) > 0 {
		if checkUser[0].Created > time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
			c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "email_already_sent")+user.Email, errorcodes.EmailAlreadySent))
			return
		} else {
			del := a.db.Model(&models.RegToken{}).Delete("user_id = ?", checkUser[0].UserId)
			if del.Error != nil {
				c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
				return
			}
		}
	}
	code := utils.CodeGen()

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "email_sent")+foundUser.Email, 0))

	go func(code string) {
		create := a.db.Model(&models.RegToken{}).Create(models.RegToken{
			UserId:  int(foundUser.ID),
			Type:    0,
			Code:    code,
			Created: dataBase.TimeNow(),
		})
		if create.Error != nil {
			a.logger.Error("Create mail in table error: " + create.Error.Error())
			return
		}

		if !utils.Send(
			user.Email,
			"Welcome to Admin Panel!", "Your link for continue is: "+os.Getenv("DOMAIN")+"/registration/submit/"+code+
				"\n\nEmail: "+foundUser.Email+
				"\nLogin: "+foundUser.Name+
				"\nName: "+foundUser.Name+
				"\nSurname: "+foundUser.Surname+
				"\nCreated: "+foundUser.Created, a.db.DB) {
			a.logger.Error("Email send error to address: " + user.Email)
		}

		a.logger.Info("Email sent to address: " + user.Email)
	}(code)
}

// @Summary Activate account
// @Description Endpoint to activate account by registration code
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body requestData.Activate true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/activate [post]
func (a *App) Activate(c *gin.Context) {
	lang := language.LangValue(c)
	var user requestData.Activate
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if user.Code == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_activation_code"), errorcodes.IncorrectActivationCode))
		return
	}
	if user.Password == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "password_null"), errorcodes.NameOfSurnameIncorrect))
		return
	}
	digit, symbols := utils.PasswordChecker(user.Password)
	if !digit || !symbols {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "password_should_by_include_digits"), errorcodes.PasswordShouldByIncludeSymbols))
		return
	}

	var activate models.RegToken

	tx := a.db.Begin()
	codesRes := tx.Model(&models.RegToken{}).Where("code = ?", user.Code).First(&activate)
	if codesRes.RowsAffected <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "activation_code_not_found"), errorcodes.ActivationCodeNotFound))
		return
	}
	// Check if token is expired
	if activate.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		if deleteCode := tx.Model(&models.RegToken{}).Delete("code = ?", activate.Code); deleteCode.Error != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
			return
		}
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "activation_code_expired"), errorcodes.ActivationCodeExpired))
		return
	}

	var foundUsers models.User
	// Check if user exist
	tx.Model(models.User{}).Where("id = ?", uint(activate.UserId)).First(&foundUsers)
	if foundUsers.ID <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorcodes.UserNotFound))
		return
	}
	// Check if user is already registered
	if foundUsers.Active {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_already_registered"), errorcodes.UserAlreadyRegistered))
		return
	}

	// Delete activation code
	if deleteCode := tx.Model(&models.RegToken{}).Where("code = ?", activate.Code).Delete(activate); deleteCode.Error != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	if foundUsers.Pass != "" {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_already_registered"), errorcodes.UserAlreadyRegistered))
		return
	}
	// Create (UPDATE) new password
	if updatePass := tx.Model(&models.User{}).Where("id = ?", foundUsers.ID).Update("pass", utils.Hash(user.Password)); updatePass.Error != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}
	// Activate user
	if update := tx.Model(&models.User{}).Where("id = ?", activate.UserId).Updates(models.User{
		Active:  true,
		Updated: dataBase.TimeNow(),
	}); update.Error != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	tx.Commit()

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "account")+foundUsers.Email+" "+language.Language(lang, "success_activate"), 0))
}

// @Summary Get new access token
// @Description Endpoint to get a new access token by refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body requestData.Refresh true "request requestData"
// @Success 200 object responses.Refresh
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Router /auth/refresh [post]
func (a *App) Refresh(c *gin.Context) {
	lang := language.LangValue(c)
	token := authorization.GetToken(c)
	var dataToken requestData.Refresh
	if err := c.ShouldBindJSON(&dataToken); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	array, errGet := a.broker.RedisGetArray(dataBase.RedisAuthTokens)
	if errGet != nil {
		return
	}
	var exist bool
	for _, item := range array {
		var tok models.RejectedToken
		er, errMarshal := json.Marshal(item)
		if errMarshal != nil {
			continue
		}
		errUnmarshal := json.Unmarshal(er, &tok)
		if errUnmarshal != nil {
			continue
		}
		if tok.RefreshToken == dataToken.Token {
			exist = true
			break
		}
	}
	if exist {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	parsedRefresh := authorization.JwtParse(dataToken.Token)
	if authorization.CheckTokenExpiration(dataToken.Token) {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	if parsedRefresh.Email == nil {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	if parsedRefresh.Email != authorization.JwtParse(token).Email {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	var user models.User
	a.db.Model(models.User{}).Where("email = ?", authorization.JwtParse(token).Email).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	access, refresh, err := authorization.GenerateJWT(authorization.TokenData{
		Authorized: true,
		Email:      user.Email,
		Role:       user.RoleId,
	})
	if err != nil {
		a.logger.Error(err)
	}

	rejectedTokens := models.RejectedToken{
		AccessToken:  token,
		RefreshToken: dataToken.Token,
	}

	err = a.db.Model(models.RejectedToken{}).Create(rejectedTokens).Error
	if err != nil {
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	if err := a.broker.RedisAddToArray(dataBase.RedisAuthTokens, rejectedTokens); err != nil {
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	c.JSON(http.StatusOK, responses.Refresh{
		AccessToken:  access,
		RefreshToken: refresh,
		UserId:       int(user.ID),
	})
}

// @Summary Logout from account
// @Description Endpoint to logout from account
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 object models.SuccessResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Router /auth/logout [post]
func (a *App) Logout(c *gin.Context) {
	lang := language.LangValue(c)
	token := authorization.GetAuth(c)
	if token == "" {
		c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "successfuly_logout"), 0))
		return
	}
	if authorization.JwtParse(token).Email == nil {
		c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "successfuly_logout"), 0))
		return
	}

	rejected := models.RejectedToken{
		AccessToken:  token,
		RefreshToken: "",
	}

	if err := a.broker.RedisAddToArray(dataBase.RedisAuthTokens, rejected); err != nil {
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	if err := a.db.Model(models.RejectedToken{}).Create(rejected).Error; err != nil {
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "successfuly_logout"), 0))
}

// @Summary Check registration code if exist
// @Description Endpoint to check registration code if exist
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.RegistrationCodeBody true "request requestData"
// @Success 200 object models.CodeCheckResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/register/check [post]
func (a *App) CheckRegistrationCode(c *gin.Context) {
	lang := language.LangValue(c)
	var code models.RegistrationCodeBody

	if err := c.ShouldBindJSON(&code); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	var foundCodes models.RegToken
	if err := a.db.Model(models.RegToken{}).Where("code = ? AND type = ?", code.Code, 0).First(&foundCodes).Error; err != nil {
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}
	if foundCodes.Code == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	var user models.User
	if err := a.db.Model(models.User{}).Where("id = ?", uint(foundCodes.UserId)).First(&user); err.Error != nil {
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}
	if user.Login == "" {
		c.JSON(http.StatusNotFound, models.ResponseMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	if foundCodes.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		if err := a.db.Model(&models.RegToken{}).Where("code = ?", foundCodes).Delete(foundCodes); err.Error != nil {
			a.logger.Error(err)
			c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
			return
		}
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "activation_code_expired"), errorcodes.ActivationCodeExpired))
		return
	}

	if user.Active {
		c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "user_already_registered"), errorcodes.UserAlreadyRegistered))
		return
	}

	c.JSON(http.StatusOK, models.CodeCheckResponse{
		ID:      user.ID,
		Name:    user.Name,
		Surname: user.Surname,
		Email:   user.Email,
	})
}

// @Summary Check recovery code if exist
// @Description Endpoint to check recovery code if exist
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body requestData.CheckRecoveryCode true "request requestData"
// @Success 200 object responses.CheckRecoveryCode
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/recovery/check [post]
func (a *App) CheckRecoveryCode(c *gin.Context) {
	lang := language.LangValue(c)
	var code requestData.CheckRecoveryCode

	if err := c.ShouldBindJSON(&code); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	var foundCodes models.RegToken
	if err := a.db.Model(models.RegToken{}).Where("code = ? AND type = ?", code.Code, 1).First(&foundCodes).Error; err != nil {
		a.logger.Error(err)
	}
	if foundCodes.Code == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	var user models.User
	if err := a.db.Model(models.User{}).Where("id = ?", uint(foundCodes.UserId)).First(&user); err.Error != nil {
		a.logger.Error(err)
	}
	if user.Login == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	if foundCodes.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		if err := a.db.Model(&models.RegToken{}).Where("code = ?", foundCodes).Delete(foundCodes); err.Error != nil {
			a.logger.Error(err)
			c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
			return
		}
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "activation_code_expired"), errorcodes.ActivationCodeExpired))
		return
	}

	c.JSON(http.StatusOK, responses.CheckRecoveryCode{
		ID:      user.ID,
		Name:    user.Name,
		Surname: user.Surname,
		Email:   user.Email,
	})
}

// @Summary Recovery user account
// @Description Endpoint to recovery user account by email
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.SendMail true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Router /auth/recovery [post]
func (a *App) Recovery(c *gin.Context) {
	lang := language.LangValue(c)
	var user models.SendMail

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if user.Email == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "email_empty"), errorcodes.EmptyEmail))
		return
	}

	// Check if user exist
	var foundUser models.User
	a.db.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "email_sent")+user.Email, 0))
		return
	}

	// Check if user already sent email
	var checkUser models.RegToken
	a.db.Model(&models.RegToken{}).Where("user_id = ? AND type = ?", foundUser.ID, 1).First(&checkUser)
	if checkUser.Created < time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
		a.db.Model(&models.RegToken{}).Where("user_id = ?", checkUser.UserId).Delete(models.RegToken{UserId: checkUser.UserId, Type: 0})
	} else {
		c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "email_already_sent")+user.Email, errorcodes.EmailAlreadySent))
		return
	}

	code := utils.CodeGen()

	// Create new code in database
	if err := a.db.Model(&models.RegToken{}).Create(models.RegToken{
		UserId:  int(foundUser.ID),
		Type:    1,
		Code:    code,
		Created: dataBase.TimeNow(),
	}); err.Error != nil {
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, "Email sent to "+foundUser.Email, 0))

	// Send email
	go func(code string) {
		utils.Send(
			foundUser.Email,
			"Admin Panel password recovery!", "Your link for continue is:  "+os.Getenv("DOMAIN")+"/recovery/submit/"+code+
				"\n\nEmail: "+user.Email+
				"\nLogin: "+foundUser.Name+
				"\nName: "+foundUser.Name+
				"\nSurname: "+foundUser.Surname+
				"\nCreated: "+foundUser.Created,
			a.db.DB)
	}(code)
}

// @Summary Recovery submit
// @Description Endpoint to submit recovery account and create a new password for account
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.RecoverySubmit true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/recovery/submit [post]
func (a *App) RecoverySubmit(c *gin.Context) {
	lang := language.LangValue(c)
	var recoveryBody models.RecoverySubmit

	err := c.ShouldBindJSON(&recoveryBody)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if recoveryBody.Code == "" || recoveryBody.Password == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "code_password_empty"), errorcodes.CodeOrPasswordEmpty))
		return
	}
	digit, symbols := utils.PasswordChecker(recoveryBody.Password)
	if !digit || !symbols {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "password_should_by_include_digits"), errorcodes.PasswordShouldByIncludeSymbols))
		return
	}

	tx := a.db.Begin()

	// Find of code
	var foundCodes models.RegToken
	err = tx.Model(models.RegToken{}).Where("code = ?", recoveryBody.Code).First(&foundCodes).Error
	if err != nil {
		tx.Rollback()
		a.logger.Error(err)
	}
	if foundCodes.Code == "" {
		c.JSON(http.StatusNotFound, models.ResponseMsg(false, language.Language(lang, "recovery_code_not_found"), errorcodes.RecoveryCodeNotFound))
		return
	}

	// Find user by code
	var foundUser models.User
	err = tx.Model(models.User{}).Where("id = ?", uint(foundCodes.UserId)).First(&foundUser).Error
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, models.ResponseMsg(false, language.Language(lang, "recovery_code_not_found"), errorcodes.RecoveryCodeNotFound))
		return
	}

	// Check if code is expired
	if foundCodes.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		tx.Model(&models.RegToken{}).Where("code = ?", foundCodes.Code).Delete(foundCodes)
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "recovery_code_expired"), errorcodes.RecoveryCodeExpired))
		return
	}

	// Hash password
	hashPassword := utils.Hash(recoveryBody.Password)

	// Delete code
	err = tx.Model(&models.RegToken{}).Where("code = ?", foundCodes.Code).Delete(foundCodes).Error
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	// Update password
	err = tx.Model(&models.User{}).Where("id = ?", foundUser.ID).Update("pass", hashPassword).Error
	if err != nil {
		tx.Rollback()
		a.logger.Error(err)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	tx.Commit()

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "password_reseted"), 0))
}
