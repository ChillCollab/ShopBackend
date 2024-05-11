package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"backend/internal/api/middlewares/auth"
	"backend/internal/dataBase"
	errorcodes "backend/internal/errorCodes"
	"backend/models"
	"backend/models/body"
	"backend/models/language"
	"backend/models/responses"
	utils "backend/pkg/utils"

	"github.com/gin-gonic/gin"
)

// Login авторизация
// @Summary Auth into account
// @Description Endpoint to login into account
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body body.Login true "request body"
// @Success 200 object responses.AuthResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Router /auth/login [post]

func (a *App) Login(c *gin.Context) {
	var user body.Login

	lang := language.LangValue(c)
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError),
		)
		return
	}

	userInfo, err := a.db.UserInfo(user.Login)
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

	accessToken, refreshToken, err := auth.GenerateJWT(auth.TokenData{
		Authorized: true,
		Email:      userInfo.Email,
		Role:       userInfo.RoleId,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	alive, err := auth.CheckTokenRemaining(accessToken)
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
// @Param body body body.Register true "request body"
// @Success 200 object models.UserRegisterComplete
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Router /auth/register [post]
func (a *App) Register(c *gin.Context) {
	lang := language.LangValue(c)
	var user body.Register
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
// @Param body body body.Send true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/activate/send [post]
func (a *App) Send(c *gin.Context) {
	lang := language.LangValue(c)
	var user body.Send

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	code := utils.CodeGen()

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

	a.db.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).Find(&checkUser)
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

	go auth.SendRegEmail(foundUser, code, 0, a.db.DB)

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "email_sent")+foundUser.Email, 0))
}

// @Summary Activate account
// @Description Endpoint to activate account by registration code
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body body.Activate true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/activate [post]
func (a *App) Activate(c *gin.Context) {
	lang := language.LangValue(c)
	var user body.Activate
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	res, err := auth.ActivateHandler(user, lang)
	if err != nil {
		c.JSON(res.Code, res.Object)
		return
	}

	usr, res, err := auth.ActivateByRegToken(user, lang, a.db.DB)
	if err != nil {
		c.JSON(res.Code, res.Object)
		return
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "account")+usr.Email+" "+language.Language(lang, "success_activate"), 0))
}

// @Summary Get new access token
// @Description Endpoint to get a new access token by refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body auth.Token true "request body"
// @Success 200 object models.AccessToken
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Router /auth/refresh [post]
func (a *App) Refresh(c *gin.Context) {
	lang := language.LangValue(c)
	token := auth.CheckAuth(c, false, a.db.DB)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	data := auth.JwtParse(token)
	if data.Email == nil {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	var dataToken body.Refresh
	if err := c.ShouldBindJSON(&dataToken); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	var user models.User
	a.db.Model(models.User{}).Where("email = ?", data.Email).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	var foundToken models.AuthToken
	a.db.Model(models.AuthToken{}).Where("access_token = ?", token).First(&foundToken)
	if foundToken.AccessToken == "" || foundToken.RefreshToken == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	if uint(foundToken.UserId) != user.ID {
		a.logger.Error("Check user access tokens. Found id != userID from jwt")
		return
	}

	if auth.CheckTokenExpiration(dataToken.Token) {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	if dataToken.Token != foundToken.RefreshToken {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	a.db.Model(models.AuthToken{}).Where("user_id = ?", strconv.Itoa(int(user.ID))).Delete(foundToken)
	access, refresh, err := auth.GenerateJWT(auth.TokenData{
		Authorized: true,
		Email:      user.Email,
	})
	if err != nil || refresh == "" || access == "" {
		panic(err)
	}

	newTokens := models.AuthToken{
		UserId:       user.ID,
		AccessToken:  access,
		RefreshToken: refresh,
	}

	a.db.Model(models.AuthToken{}).Create(newTokens)
	c.JSON(http.StatusOK, newTokens)
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
	token := auth.GetAuth(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	var foundToken []models.AuthToken
	a.db.Model(models.AuthToken{}).Where("access_token = ?", token).Find(&foundToken)
	if len(foundToken) == 0 {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	if len(foundToken) > 1 {
		c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorcodes.MultipleData))
		return
	}

	a.db.Model(models.AuthToken{}).Where("access_token = ?", foundToken[0].AccessToken).Delete(&foundToken)
	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "successfuly_logout"), 0))
}

// @Summary Check registration code if exist
// @Description Endpoint to check registration code if exist
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.RegistrationCodeBody true "request body"
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

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &code); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	var foundCodes []models.RegToken

	a.db.Model(models.RegToken{}).Where("code = ?", code.Code).Find(&foundCodes)
	if len(foundCodes) <= 0 || foundCodes[0].Type != 0 {
		c.JSON(http.StatusNotFound, models.ResponseMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	var user []models.User
	a.db.Model(models.User{}).Where("id = ?", uint(foundCodes[0].UserId)).Find(&user)
	if len(user) <= 0 {
		c.JSON(http.StatusNotFound, models.ResponseMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	if foundCodes[0].Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		a.db.Model(&models.RegToken{}).Where("code = ?", foundCodes[0]).Delete(foundCodes[0])
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "activation_code_expired"), errorcodes.ActivationCodeExpired))
		return
	}

	if user[0].Active {
		c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "user_already_registered"), errorcodes.UserAlreadyRegistered))
		return
	}

	c.JSON(http.StatusOK, models.CodeCheckResponse{
		ID:      user[0].ID,
		Name:    user[0].Name,
		Surname: user[0].Surname,
		Email:   user[0].Email,
	})
}

// @Summary Recovery user account
// @Description Endpoint to recovery user account by email
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.SendMail true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Router /auth/recovery [post]
func (a *App) Recovery(c *gin.Context) {
	lang := language.LangValue(c)
	var user models.SendMail

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Parse error",
		})
		return
	}
	if user.Email == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "email_empty"), errorcodes.EmptyEmail))
		return
	}

	var foundUser models.User
	a.db.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "email_sent")+user.Email, 0))
		return
	}

	var checkUser models.RegToken

	a.db.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).First(&checkUser)
	if checkUser.Created < time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
		a.db.Model(&models.RegToken{}).Where("user_id = ?", checkUser.UserId).Delete(models.RegToken{UserId: checkUser.UserId, Type: 0})
	} else {
		c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "email_already_sent")+user.Email, errorcodes.EmailAlreadySent))
		return
	}

	code := utils.CodeGen()

	if utils.Send(
		foundUser.Email,
		"Admin Panel password recovery!", "Your link for countinue is:  "+os.Getenv("DOMAIN")+"/acc/activate/"+code+
			"\n\nEmail: "+user.Email+
			"\nLogin: "+foundUser.Name+
			"\nName: "+foundUser.Name+
			"\nSurname: "+foundUser.Surname+
			"\nCreated: "+foundUser.Created,
		a.db.DB) {
		a.db.Model(&models.RegToken{}).Create(models.RegToken{
			UserId:  int(foundUser.ID),
			Type:    1,
			Code:    code,
			Created: dataBase.TimeNow(),
		})
		c.JSON(http.StatusOK, models.ResponseMsg(true, "Email sent to "+foundUser.Email, 0))
		return
	} else {
		c.JSON(http.StatusForbidden, models.ResponseMsg(false, language.Language(lang, "email_error"), errorcodes.EmailSendError))
		return
	}
}

// @Summary Recovery submit
// @Description Endpoint to submit recovery account and create a new password for account
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.RecoverySubmit true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/recovery/submit [post]
func (a *App) RecoverySubmit(c *gin.Context) {
	lang := language.LangValue(c)
	var recoveryBody models.RecoverySubmit

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &recoveryBody); err != nil {
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

	var foundCodes []models.RegToken
	a.db.Model(models.RegToken{}).Where("code = ?", recoveryBody.Code).Find(&foundCodes)
	if len(foundCodes) <= 0 || len(foundCodes) > 1 || foundCodes[0].Type != 1 {
		c.JSON(http.StatusNotFound, models.ResponseMsg(false, language.Language(lang, "recovery_code_not_found"), errorcodes.RecoveryCodeNotFound))
		return
	}

	var foundUser []models.User
	a.db.Model(models.User{}).Where("id = ?", uint(foundCodes[0].UserId)).Find(&foundUser)
	if len(foundUser) <= 0 || len(foundUser) > 1 {
		a.db.Model(models.RegToken{}).Delete(foundCodes)
		c.JSON(http.StatusNotFound, models.ResponseMsg(false, language.Language(lang, "recovery_code_not_found"), errorcodes.RecoveryCodeNotFound))
		return
	}

	if foundCodes[0].Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		a.db.Model(&models.RegToken{}).Where("code = ?", foundCodes[0].Code).Delete(foundCodes[0])
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "recovery_code_expired"), errorcodes.RecoveryCodeExpired))
		return
	}

	hashPassword := utils.Hash(recoveryBody.Password)
	fmt.Println(len(foundUser))

	var foundPass []models.UserPass
	a.db.Model(models.UserPass{}).Where("user_id = ?", foundUser[0].ID).Find(&foundPass)
	fmt.Print(len(foundPass))
	if len(foundPass) <= 0 {
		a.db.Model(models.UserPass{}).Create(models.UserPass{
			UserId:  foundUser[0].ID,
			Pass:    hashPassword,
			Updated: dataBase.TimeNow(),
		})
	} else if len(foundPass) == 1 {
		a.db.Model(&models.UserPass{}).Where("user_id = ?", foundUser[0].ID).UpdateColumn("pass", hashPassword)
		a.db.Model(&models.UserPass{}).Where("user_id = ?", foundUser[0].ID).UpdateColumn("updated", dataBase.TimeNow())
	} else {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorcodes.MultipleData))
		return
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "password_reseted"), 0))
}
