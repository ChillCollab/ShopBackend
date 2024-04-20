package authController

import (
	dataBase "backend/internal/dataBase/models"
	errorcodes "backend/internal/errorCodes"
	"backend/internal/middlewares/auth"
	"backend/internal/middlewares/handlers"
	"backend/internal/middlewares/language"
	"backend/models"
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
// @Param body body models.UserLogin true "request body"
// @Success 200 object models.UserLoginInfo
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Router /auth/login [post]
func Login(c *gin.Context) {
	var user models.UserLogin

	lang := language.LangValue(c)

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if err := utils.JsonChecker(user, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.UnmarshalError))
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "unmarshal_error"), errorcodes.UnmarshalError))
		return
	}

	var foundUserByEmail []models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Login).Find(&foundUserByEmail)

	var foundUserByLogin []models.User
	dataBase.DB.Model(&models.User{}).Where("login = ?", user.Login).Find(&foundUserByLogin)

	var foundUser []models.User
	if len(foundUserByLogin) <= 0 {
		foundUser = foundUserByEmail
	} else {
		foundUser = foundUserByLogin
	}
	if len(foundUser) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	} else if len(foundUser) > 1 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "multiple_data"), errorcodes.MultipleData))
		return
	}
	if !foundUser[0].Active {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "user")+" "+user.Login+" "+language.Language(lang, "is_not_active"), errorcodes.UserIsNotActive))
		return
	}

	var passCheck models.UserPass
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", foundUser[0].ID).First(&passCheck)
	userPass := utils.Hash(user.Password)
	if userPass != passCheck.Pass {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	var userRole models.UserRole
	dataBase.DB.Model(models.UserRole{}).Where("id = ?", foundUser[0].ID).First(&userRole)

	access, refresh, err := auth.GenerateJWT(auth.TokenData{
		Authorized: true,
		Email:      foundUser[0].Email,
		Role:       userRole.Role,
	})
	if err != nil || refresh == "" || access == "" {
		panic(err)
	}

	var jwtCheck models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", strconv.Itoa(int(passCheck.UserId))).First(&jwtCheck)
	data := auth.JwtParse(jwtCheck.AccessToken)
	var foundUsr []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", data.Email).Find(&foundUsr)
	if jwtCheck.AccessToken != "" && jwtCheck.RefreshToken != "" {
		expRefresh := auth.CheckTokenExpiration(jwtCheck.RefreshToken)
		expAccess := auth.CheckTokenExpiration(jwtCheck.AccessToken)
		if expAccess || expRefresh {
			dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", strconv.Itoa(int(passCheck.UserId))).Delete(jwtCheck)
		} else if len(foundUsr) <= 0 {
			dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", strconv.Itoa(int(passCheck.UserId))).Delete(jwtCheck)
		} else {

			rem, err := auth.CheckTokenRemaining(jwtCheck.AccessToken, c)
			if err != nil {
				panic(err)
			}
			c.JSON(http.StatusOK, models.UserLoginInfo{
				Info:         foundUser[0],
				AccessToken:  jwtCheck.AccessToken,
				RefreshToken: jwtCheck.RefreshToken,
				Alive:        rem,
			})
			return
		}
	}

	dataBase.DB.Model(models.AccessToken{}).Create(models.AccessToken{
		UserId:       foundUser[0].ID,
		AccessToken:  access,
		RefreshToken: refresh,
	})
	rem, err := auth.CheckTokenRemaining(access, c)
	if err != nil {
		panic(err)
	}
	c.JSON(http.StatusOK, models.UserLoginInfo{
		Info:         foundUser[0],
		AccessToken:  access,
		RefreshToken: refresh,
		Alive:        rem,
	})
}

// @Summary Register account
// @Description Endpoint to register a new user account
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.UserRegister true "request body"
// @Success 200 object models.UserRegisterComplete
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Router /auth/register [post]
func Register(c *gin.Context) {
	lang := language.LangValue(c)
	var user models.UserRegister

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if user.Name == "" || user.Surname == "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "incorrect_name_or_surname"), errorcodes.NameOfSurnameIncorrect))
		return
	} else if !utils.MailValidator(user.Email) {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "incorrect_email"), errorcodes.IncorrectEmail))
		return
	} else if user.Login == "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "login_empty"), errorcodes.LoginCanBeEmpty))
		return
	}

	if len(user.Name) > 32 || len(user.Surname) > 32 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "name_surname_long"), errorcodes.IncorrectInfoData))
		return
	}

	if ok := utils.ValidateLogin(user.Login); !ok {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "login_can_be_include_letters_digits"), errorcodes.IncorrectLogin))
		return
	}

	var ifExist []models.User

	dataBase.DB.Where("email = ?", user.Email).Find(&ifExist)
	if len(ifExist) > 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "user_already_exist"), errorcodes.UserAlreadyExist))
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

	create := dataBase.DB.Model(&models.User{}).Create(&completeUser)

	if create.Error != nil {
		fmt.Println("DB Error:", create.Error)
		c.JSON(http.StatusForbidden, handlers.ErrMsg(false, language.Language(lang, "db_error"), errorcodes.DBError))
		return
	}

	var createdUser []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", completeUser.Email).Find(&createdUser)
	if len(createdUser) <= 0 {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, language.Language(lang, "created_user_not_found"), errorcodes.NotFoundInUsers))
		return
	}

	dataBase.DB.Model(models.UserRole{}).Create(&models.UserRole{ID: createdUser[0].ID, Role: 0, Updated: dataBase.TimeNow()})

	c.JSON(http.StatusOK, models.UserRegisterComplete{
		Error: false,
		User:  completeUser,
	})
}

// @Summary Send register email
// @Description Endpoint to send register email to submit registration
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.SendMail true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 404 object models.ErrorResponse
// @Failure 500
// @Router /auth/activate/send [post]
func Send(c *gin.Context) {
	lang := language.LangValue(c)
	var user models.SendMail

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if err := utils.JsonChecker(user, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if user.Email == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "user_not_registered"), errorcodes.UserNotFound))
		return
	}

	var foundUser models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(http.StatusNotFound, handlers.ErrMsg(false, language.Language(lang, "user_not_found"), errorcodes.UserNotFound))
		return
	}

	var checkUser []models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).Find(&checkUser)
	if len(checkUser) > 1 {
		dataBase.DB.Model(&checkUser).Delete(checkUser)
		c.JSON(http.StatusForbidden, handlers.ErrMsg(false, language.Language(lang, "multiple_data"), errorcodes.MultipleData))
		return
	}
	if len(checkUser) > 0 {
		if checkUser[0].Created < time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
			dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", checkUser[0].UserId).Delete(models.RegToken{UserId: checkUser[0].UserId, Type: 0})
		} else {
			c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "email_already_sent")+user.Email, errorcodes.EmailAlreadySent))
			return
		}
	}

	code := utils.CodeGen()

	if utils.Send(
		foundUser.Email,
		"Welcome to Admin Panel!", "Your link for countinue is: "+os.Getenv("DOMAIN")+"/registration/submit/"+code+
			"\n\nEmail: "+user.Email+
			"\nLogin: "+foundUser.Name+
			"\nName: "+foundUser.Name+
			"\nSurname: "+foundUser.Surname+
			"\nCreated: "+foundUser.Created,
		dataBase.DB) {
		dataBase.DB.Model(&models.RegToken{}).Create(models.RegToken{
			UserId:  int(foundUser.ID),
			Type:    0,
			Code:    code,
			Created: dataBase.TimeNow(),
		})
		c.JSON(http.StatusOK, handlers.ErrMsg(true, language.Language(lang, "email_sent")+foundUser.Email, 0))
		return
	} else {
		c.JSON(http.StatusForbidden, handlers.ErrMsg(false, language.Language(lang, "email_error"), errorcodes.EmailSendError))
		return
	}
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
		c.JSON(http.StatusNotFound, handlers.ErrMsg(false, language.Language(lang, "incorrect_activation_code"), errorcodes.IncorrectActivationCode))
		return
	}
	if user.Password == "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "password_null"), errorcodes.NameOfSurnameIncorrect))
		return
	}
	digit, symb := utils.PasswordChecker(user.Password)
	if !digit || !symb {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "password_should_by_include_digits"), errorcodes.PasswordShouldByIncludeSymbols))
		return
	}

	var activate []models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("code = ?", user.Code).Find(&activate)
	if len(activate) <= 0 || activate[0].Type != 0 {
		c.JSON(http.StatusNotFound, handlers.ErrMsg(false, language.Language(lang, "activation_code_not_found"), errorcodes.ActivationCodeNotFound))
		return
	}
	if activate[0].Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("code = ?", activate[0].Code).Delete(activate)
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "activation_code_expired"), errorcodes.ActivationCodeExpired))
		return
	}

	var foundUsers []models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", uint(activate[0].UserId)).Find(&foundUsers)
	if len(foundUsers) <= 0 {
		c.JSON(http.StatusNotFound, handlers.ErrMsg(false, language.Language(lang, "user_not_found"), errorcodes.UserNotFound))
		return
	}

	if foundUsers[0].Active {
		c.JSON(http.StatusForbidden, handlers.ErrMsg(false, language.Language(lang, "user_already_registered"), errorcodes.UserAlreadyRegistered))
		return
	}

	var checkPass []models.UserPass
	dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", activate[0].UserId).Find(&checkPass)
	if len(checkPass) == 1 {
		if checkPass[0].Pass != "" {
			dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", activate[0].UserId).Delete(checkPass)
		}
	} else if len(checkPass) > 1 {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, language.Language(lang, "multiple_error"), errorcodes.MultipleData))
		return
	}
	dataBase.DB.Model(&models.RegToken{}).Where("code = ?", activate[0].Code).Delete(activate)
	dataBase.DB.Model(&models.UserPass{}).Create(models.UserPass{
		UserId:  uint(activate[0].UserId),
		Pass:    utils.Hash(user.Password),
		Updated: dataBase.TimeNow(),
	})
	dataBase.DB.Model(&models.User{}).Where("id = ?", activate[0].UserId).Update("active", true)

	c.JSON(http.StatusOK, handlers.ErrMsg(true, language.Language(lang, "account")+foundUsers[0].Email+" "+language.Language(lang, "success_activate"), 0))
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
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	data := auth.JwtParse(token)
	if data.Email == nil {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	var dataToken auth.Token
	if err := utils.JsonChecker(dataToken, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &dataToken); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "unmarshal_error"), errorcodes.UnmarshalError))
		return
	}

	var user models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", data.Email).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	var foundToken models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", token).First(&foundToken)
	if foundToken.AccessToken == "" || foundToken.RefreshToken == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	if uint(foundToken.UserId) != user.ID {
		panic("Check user access tokens. Found id != userID from jwt")
	}

	if auth.CheckTokenExpiration(dataToken.Token) {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}

	if dataToken.Token != foundToken.RefreshToken {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
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
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	var foundToken []models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", token).Find(&foundToken)
	if len(foundToken) == 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorcodes.Unauthorized))
		return
	}
	if len(foundToken) > 1 {
		c.JSON(http.StatusForbidden, handlers.ErrMsg(false, language.Language(lang, "multiple_data"), errorcodes.MultipleData))
		return
	}

	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", foundToken[0].AccessToken).Delete(&foundToken)
	c.JSON(http.StatusOK, handlers.ErrMsg(true, language.Language(lang, "successfuly_logout"), 0))
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
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if err := utils.JsonChecker(code, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &code); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	var foundCodes []models.RegToken

	dataBase.DB.Model(models.RegToken{}).Where("code = ?", code.Code).Find(&foundCodes)
	if len(foundCodes) <= 0 || foundCodes[0].Type != 0 {
		c.JSON(http.StatusNotFound, handlers.ErrMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	var user []models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", uint(foundCodes[0].UserId)).Find(&user)
	if len(user) <= 0 {
		c.JSON(http.StatusNotFound, handlers.ErrMsg(false, language.Language(lang, "register_code_not_found"), errorcodes.NotFoundRegistrationCode))
		return
	}

	if foundCodes[0].Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("code = ?", foundCodes[0]).Delete(foundCodes[0])
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "activation_code_expired"), errorcodes.ActivationCodeExpired))
		return
	}

	if user[0].Active {
		c.JSON(http.StatusForbidden, handlers.ErrMsg(false, language.Language(lang, "user_already_registered"), errorcodes.UserAlreadyRegistered))
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
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}
	if err := utils.JsonChecker(user, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Parse error",
		})
		return
	}
	if user.Email == "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "email_empty"), errorcodes.EmptyEmail))
		return
	}

	var foundUser models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(http.StatusOK, handlers.ErrMsg(true, language.Language(lang, "email_sent")+user.Email, 0))
		return
	}

	var checkUser models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).First(&checkUser)
	if checkUser.Created < time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", checkUser.UserId).Delete(models.RegToken{UserId: checkUser.UserId, Type: 0})
	} else {
		c.JSON(http.StatusForbidden, handlers.ErrMsg(false, language.Language(lang, "email_already_sent")+user.Email, errorcodes.EmailAlreadySent))
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
		c.JSON(http.StatusOK, handlers.ErrMsg(true, "Email sent to "+foundUser.Email, 0))
		return
	} else {
		c.JSON(http.StatusForbidden, handlers.ErrMsg(false, language.Language(lang, "email_error"), errorcodes.EmailSendError))
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
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if err := utils.JsonChecker(recoveryBody, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &recoveryBody); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "parse_error"), errorcodes.ParsingError))
		return
	}

	if recoveryBody.Code == "" || recoveryBody.Password == "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "code_password_empty"), errorcodes.CodeOrPasswordEmpty))
		return
	}

	digit, symbols := utils.PasswordChecker(recoveryBody.Password)
	if !digit || !symbols {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "password_should_by_include_digits"), errorcodes.PasswordShouldByIncludeSymbols))
		return
	}

	var foundCodes []models.RegToken
	dataBase.DB.Model(models.RegToken{}).Where("code = ?", recoveryBody.Code).Find(&foundCodes)
	if len(foundCodes) <= 0 || len(foundCodes) > 1 || foundCodes[0].Type != 1 {
		c.JSON(http.StatusNotFound, handlers.ErrMsg(false, language.Language(lang, "recovery_code_not_found"), errorcodes.RecoveryCodeNotFound))
		return
	}

	var foundUser []models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", uint(foundCodes[0].UserId)).Find(&foundUser)
	if len(foundUser) <= 0 || len(foundUser) > 1 {
		dataBase.DB.Model(models.RegToken{}).Delete(foundCodes)
		c.JSON(http.StatusNotFound, handlers.ErrMsg(false, language.Language(lang, "recovery_code_not_found"), errorcodes.RecoveryCodeNotFound))
		return
	}

	if foundCodes[0].Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("code = ?", foundCodes[0].Code).Delete(foundCodes[0])
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "recovery_code_expired"), errorcodes.RecoveryCodeExpired))
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
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, language.Language(lang, "multiple_data"), errorcodes.MultipleData))
		return
	}

	c.JSON(http.StatusOK, handlers.ErrMsg(true, language.Language(lang, "password_reseted"), 0))
}
