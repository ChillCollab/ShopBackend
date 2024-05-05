package controllers

import (
	dataBase "backend/internal/dataBase/models"
	errorcodes "backend/internal/errorCodes"
	"backend/internal/middlewares/auth"
	"backend/internal/middlewares/db"
	"backend/internal/middlewares/handlers"
	"backend/internal/middlewares/language"
	"backend/models"
	"backend/models/body"
	"backend/models/responses"
	utils "backend/pkg/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

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
func Login(c *gin.Context) {
	var user body.Login

	lang := language.LangValue(c)

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	userInfo, tokens, err := db.UserInfo(user.Login)
	if err != nil {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	if !userInfo.Active {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "user")+" "+user.Login+" "+language.Language(lang, "is_not_active"), errorcodes.UserIsNotActive))
		return
	}

	userPass := utils.Hash(user.Password)
	if userPass != userInfo.Pass {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	authResponse := responses.AuthResponse{
		User: responses.UserInfo{
			Login:   userInfo.Login,
			Name:    userInfo.Name,
			Surname: userInfo.Surname,
			Email:   userInfo.Email,
			Phone:   userInfo.Phone,
			Role:    userInfo.Role,
		},
	}

	tokens, errors := auth.CheckTokens(userInfo, models.AccessToken{UserId: userInfo.ID, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken})
	if errors != nil {
		c.JSON(http.StatusInternalServerError, errors)
		return
	}

	alive, err := auth.CheckTokenRemaining(tokens.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	authResponse.AccessToken = tokens.AccessToken
	authResponse.RefreshToken = tokens.RefreshToken
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
func Register(c *gin.Context) {
	lang := language.LangValue(c)

	var user body.Register

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	success, res := auth.RegisterHandler(user, lang)
	if !success {
		c.JSON(res.Code, res.Object)
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

	createRes, err := auth.CreateUser(completeUser, lang)
	if err != nil {
		c.JSON(createRes.Code, createRes.Object)
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
		},
	})
}

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
func Send(c *gin.Context) {
	lang := language.LangValue(c)
	var user body.Send

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	code := utils.CodeGen()

	foundUser, response, err := auth.SendHanlder(models.User{Email: user.Email}, lang)
	if err != nil {
		c.JSON(response.Code, response.Object)
		return
	}

	go auth.SendRegEmail(foundUser, code, 0)

	c.JSON(http.StatusOK, handlers.ResponseMsg(true, language.Language(lang, "email_sent")+foundUser.Email, 0))
}

// @Summary Activate account
// @Description Endpoint to activate account by registration code
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.ActivateBody true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/activate [post]
func Activate(c *gin.Context) {
	lang := language.LangValue(c)
	var user models.ActivateBody
	err := c.ShouldBindJSON(&user)
	if err != nil {
		panic(err)
	}
	if user.Code == "" {
		c.JSON(http.StatusNotFound, handlers.ResponseMsg(false, language.Language(lang, "incorrect_activation_code"), errorcodes.IncorrectActivationCode))
		return
	}
	if user.Password == "" {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "password_null"), errorcodes.NameOfSurnameIncorrect))
		return
	}
	digit, symb := utils.PasswordChecker(user.Password)
	if !digit || !symb {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "password_should_by_include_digits"), errorcodes.PasswordShouldByIncludeSymbols))
		return
	}

	var activate []models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("code = ?", user.Code).Find(&activate)
	if len(activate) <= 0 || activate[0].Type != 0 {
		c.JSON(http.StatusNotFound, handlers.ResponseMsg(false, language.Language(lang, "activation_code_not_found"), errorcodes.ActivationCodeNotFound))
		return
	}
	if activate[0].Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("code = ?", activate[0].Code).Delete(activate)
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "activation_code_expired"), errorcodes.ActivationCodeExpired))
		return
	}

	var foundUsers []models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", uint(activate[0].UserId)).Find(&foundUsers)
	if len(foundUsers) <= 0 {
		c.JSON(http.StatusNotFound, handlers.ResponseMsg(false, language.Language(lang, "user_not_found"), errorcodes.UserNotFound))
		return
	}

	if foundUsers[0].Active {
		c.JSON(http.StatusForbidden, handlers.ResponseMsg(false, language.Language(lang, "user_already_registered"), errorcodes.UserAlreadyRegistered))
		return
	}

	var checkPass []models.UserPass
	dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", activate[0].UserId).Find(&checkPass)
	if len(checkPass) == 1 {
		if checkPass[0].Pass != "" {
			dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", activate[0].UserId).Delete(checkPass)
		}
	} else if len(checkPass) > 1 {
		c.JSON(http.StatusInternalServerError, handlers.ResponseMsg(false, language.Language(lang, "multiple_error"), errorcodes.MultipleData))
		return
	}
	dataBase.DB.Model(&models.RegToken{}).Where("code = ?", activate[0].Code).Delete(activate)
	dataBase.DB.Model(&models.UserPass{}).Create(models.UserPass{
		UserId:  uint(activate[0].UserId),
		Pass:    utils.Hash(user.Password),
		Updated: dataBase.TimeNow(),
	})
	dataBase.DB.Model(&models.User{}).Where("id = ?", activate[0].UserId).Update("active", true)

	c.JSON(http.StatusOK, handlers.ResponseMsg(true, language.Language(lang, "account")+foundUsers[0].Email+" "+language.Language(lang, "success_activate"), 0))
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
func Refresh(c *gin.Context) {
	lang := language.LangValue(c)
	token := auth.CheckAuth(c, false)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	data := auth.JwtParse(token)
	if data.Email == nil {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	var dataToken auth.Token
	if err := json.Unmarshal(rawData, &dataToken); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorcodes.UnmarshalError))
		return
	}

	var user models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", data.Email).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	var foundToken models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", token).First(&foundToken)
	if foundToken.AccessToken == "" || foundToken.RefreshToken == "" {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	if uint(foundToken.UserId) != user.ID {
		panic("Check user access tokens. Found id != userID from jwt")
	}

	if auth.CheckTokenExpiration(dataToken.Token) {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	if dataToken.Token != foundToken.RefreshToken {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", strconv.Itoa(int(user.ID))).Delete(foundToken)
	access, refresh, err := auth.GenerateJWT(auth.TokenData{
		Authorized: true,
		Email:      user.Email,
	})
	if err != nil || refresh == "" || access == "" {
		panic(err)
	}

	newTokens := models.AccessToken{
		UserId:       user.ID,
		AccessToken:  access,
		RefreshToken: refresh,
	}

	dataBase.DB.Model(models.AccessToken{}).Create(newTokens)
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
func Logout(c *gin.Context) {
	lang := language.LangValue(c)
	token := auth.GetAuth(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	var foundToken []models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", token).Find(&foundToken)
	if len(foundToken) == 0 {
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	if len(foundToken) > 1 {
		c.JSON(http.StatusForbidden, handlers.ResponseMsg(false, language.Language(lang, "multiple_error"), errorcodes.MultipleData))
		return
	}

	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", foundToken[0].AccessToken).Delete(&foundToken)
	c.JSON(http.StatusOK, handlers.ResponseMsg(true, language.Language(lang, "successfuly_logout"), 0))
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
func CheckRegistrationCode(c *gin.Context) {
	lang := language.LangValue(c)
	var code models.RegistrationCodeBody

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &code); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	var foundCodes []models.RegToken

	dataBase.DB.Model(models.RegToken{}).Where("code = ?", code.Code).Find(&foundCodes)
	if len(foundCodes) <= 0 || foundCodes[0].Type != 0 {
		c.JSON(http.StatusNotFound, handlers.ResponseMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	var user []models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", uint(foundCodes[0].UserId)).Find(&user)
	if len(user) <= 0 {
		c.JSON(http.StatusNotFound, handlers.ResponseMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	if foundCodes[0].Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("code = ?", foundCodes[0]).Delete(foundCodes[0])
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "activation_code_expired"), errorcodes.ActivationCodeExpired))
		return
	}

	if user[0].Active {
		c.JSON(http.StatusForbidden, handlers.ResponseMsg(false, language.Language(lang, "user_already_registered"), errorcodes.UserAlreadyRegistered))
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
func Recovery(c *gin.Context) {
	lang := language.LangValue(c)
	var user models.SendMail

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Parse error",
		})
		return
	}
	if user.Email == "" {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "email_empty"), errorcodes.EmptyEmail))
		return
	}

	var foundUser models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(http.StatusOK, handlers.ResponseMsg(true, language.Language(lang, "email_sent")+user.Email, 0))
		return
	}

	var checkUser models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).First(&checkUser)
	if checkUser.Created < time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", checkUser.UserId).Delete(models.RegToken{UserId: checkUser.UserId, Type: 0})
	} else {
		c.JSON(http.StatusForbidden, handlers.ResponseMsg(false, language.Language(lang, "email_already_sent")+user.Email, errorcodes.EmailAlreadySent))
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
		dataBase.DB) {
		dataBase.DB.Model(&models.RegToken{}).Create(models.RegToken{
			UserId:  int(foundUser.ID),
			Type:    1,
			Code:    code,
			Created: dataBase.TimeNow(),
		})
		c.JSON(http.StatusOK, handlers.ResponseMsg(true, "Email sent to "+foundUser.Email, 0))
		return
	} else {
		c.JSON(http.StatusForbidden, handlers.ResponseMsg(false, language.Language(lang, "email_error"), errorcodes.EmailSendError))
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
func RecoverySubmit(c *gin.Context) {
	lang := language.LangValue(c)
	var recoveryBody models.RecoverySubmit

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &recoveryBody); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if recoveryBody.Code == "" || recoveryBody.Password == "" {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "code_password_empty"), errorcodes.CodeOrPasswordEmpty))
		return
	}

	digit, symbols := utils.PasswordChecker(recoveryBody.Password)
	if !digit || !symbols {
		c.JSON(http.StatusBadRequest, handlers.ResponseMsg(false, language.Language(lang, "password_should_by_include_digits"), errorcodes.PasswordShouldByIncludeSymbols))
		return
	}

	var foundCodes []models.RegToken
	dataBase.DB.Model(models.RegToken{}).Where("code = ?", recoveryBody.Code).Find(&foundCodes)
	if len(foundCodes) <= 0 || len(foundCodes) > 1 || foundCodes[0].Type != 1 {
		c.JSON(http.StatusNotFound, handlers.ResponseMsg(false, language.Language(lang, "recovery_code_not_found"), errorcodes.RecoveryCodeNotFound))
		return
	}

	var foundUser []models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", uint(foundCodes[0].UserId)).Find(&foundUser)
	if len(foundUser) <= 0 || len(foundUser) > 1 {
		dataBase.DB.Model(models.RegToken{}).Delete(foundCodes)
		c.JSON(http.StatusNotFound, handlers.ResponseMsg(false, language.Language(lang, "recovery_code_not_found"), errorcodes.RecoveryCodeNotFound))
		return
	}

	if foundCodes[0].Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("code = ?", foundCodes[0].Code).Delete(foundCodes[0])
		c.JSON(http.StatusUnauthorized, handlers.ResponseMsg(false, language.Language(lang, "recovery_code_expired"), errorcodes.RecoveryCodeExpired))
		return
	}

	hashPassword := utils.Hash(recoveryBody.Password)
	fmt.Println(len(foundUser))

	var foundPass []models.UserPass
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", foundUser[0].ID).Find(&foundPass)
	fmt.Print(len(foundPass))
	if len(foundPass) <= 0 {
		dataBase.DB.Model(models.UserPass{}).Create(models.UserPass{
			UserId:  foundUser[0].ID,
			Pass:    hashPassword,
			Updated: dataBase.TimeNow(),
		})
	} else if len(foundPass) == 1 {
		dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", foundUser[0].ID).UpdateColumn("pass", hashPassword)
		dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", foundUser[0].ID).UpdateColumn("updated", dataBase.TimeNow())
	} else {
		c.JSON(http.StatusInternalServerError, handlers.ResponseMsg(false, language.Language(lang, "multiple_error"), errorcodes.MultipleData))
		return
	}

	c.JSON(http.StatusOK, handlers.ResponseMsg(true, language.Language(lang, "password_reseted"), 0))
}
