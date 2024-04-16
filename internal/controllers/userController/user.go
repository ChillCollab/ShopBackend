package userController

import (
	dataBase "backend_v1/internal/dataBase/models"
	"backend_v1/internal/errorCodes"
	"backend_v1/internal/middlewares/auth"
	"backend_v1/internal/middlewares/handlers"
	"backend_v1/models"
	"backend_v1/pkg/utils"
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
	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	email := auth.JwtParse(token).Email
	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	var roles []models.UserRole
	dataBase.DB.Model(models.UserRole{}).Where("id = ?", users[0].ID).Find(&roles)

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
// @Success 200 array models.SuccessResponse
// @Failure 401 object models.ErrorResponse
// @Failure 403 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/changepass [post]
func ChangePassword(c *gin.Context) {
	var passwordData models.ChangePassword

	rawData, err := c.GetRawData()

	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Pasing error", errorCodes.ParsingError))
		return
	}
	if err := utils.JsonChecker(passwordData, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &passwordData); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Unmarshal error", errorCodes.ParsingError))
		return
	}

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}
	email := auth.JwtParse(token).Email
	var users []models.User
	var userPass []models.UserPass
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", users[0].ID).Find(&userPass)

	if len(userPass) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	} else if len(userPass) > 1 {
		panic("duplicate data")
	}
	hashOldPass := utils.Hash(passwordData.OldPassword)
	if userPass[0].Pass != hashOldPass {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Incorrect old password", errorCodes.IncorrectOldPassword))
		return
	}
	digts, symbol := utils.PasswordChecker(passwordData.NewPassword)
	if !digts && !symbol {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Password must be include Digits and Symbols", errorCodes.PasswordShouldByIncludeSymbols))
		return
	}
	hashNewPass := utils.Hash(passwordData.NewPassword)
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", users[0].ID).Update("pass", hashNewPass)

	c.JSON(http.StatusOK, handlers.ErrMsg(true, "Password updated", 0))
}

// @Summary Change user data
// @Description Endpoint to change user data
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.ChangeUserInfo true "request body"
// @Success 200 array models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change [patch]
func ChangeOwnData(c *gin.Context) {
	var user models.ChangeUserInfo

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Unmarshal error", errorCodes.ParsingError))
		return
	}

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	email := auth.JwtParse(token).Email

	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	if user.Login != "" {
		if ok := utils.ValidateLogin(user.Login); !ok {
			c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Login must be include only letters and digits not more 32", errorCodes.IncorrectLogin))
			return
		}
	}

	if len(user.Name) > 32 || len(user.Surname) > 32 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Name and Surname must be not more 32", errorCodes.IncorrectInfoData))
		return
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

	c.JSON(http.StatusOK, handlers.ErrMsg(true, "User data updated", 0))

}

// @Summary Change user email
// @Description Endpoint to change user email
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.EmailChangeRequest true "request body"
// @Success 200 array models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email [post]
func ChangeEmail(c *gin.Context) {
	var emailData models.EmailChangeRequest

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &emailData); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Unmarshal error", errorCodes.ParsingError))
		return
	}
	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	email := auth.JwtParse(token).Email

	var users []models.User

	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)

	if len(users) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "User not found", errorCodes.UsersNotFound))
		return
	} else if len(users) > 1 {
		panic("duplicate data")
	}

	if valid := utils.MailValidator(emailData.Email); !valid {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Invalid email format", errorCodes.IncorrectEmail))
		return
	}

	var foundCode []models.EmailChange

	dataBase.DB.Model(models.EmailChange{}).Where("user_id = ?", users[0].ID).Find(&foundCode)
	if len(foundCode) > 0 || len(foundCode) > 1 {
		dataBase.DB.Model(models.EmailChange{}).Where("user_id = ?", users[0].ID).Delete(&foundCode)
	}

	code := utils.GenerateNumberCode()
	newEmail := models.EmailChange{
		UserID:  users[0].ID,
		Email:   emailData.Email,
		Code:    code,
		Created: dataBase.TimeNow(),
	}

	dataBase.DB.Model(models.EmailChange{}).Create(&newEmail)
	sent := utils.Send(users[0].Email, "Email change", "Your submit code: "+strconv.Itoa(newEmail.Code))
	if !sent {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, "Error sending email", errorCodes.EmailSendError))
		return
	}

	c.JSON(http.StatusOK, handlers.ErrMsg(true, "Code sent to email "+users[0].Email, 0))
}

// @Summary Change email complete
// @Description Endpoint to complete email change
// @Tags User
// @Accept json
// @Produce json
// @Param body body models.EmailChangeComplete true "request body"
// @Success 200 array models.EmailChangeResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email/submit [patch]
func ChangeEmailComplete(c *gin.Context) {
	var completeBody models.EmailChangeComplete

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parsing Error!", errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &completeBody); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Unmarshal error", errorCodes.ParsingError))
		return
	}

	if err := utils.JsonChecker(completeBody, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorCodes.ParsingError))
		return
	}

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password", errorCodes.Unauthorized))
		return
	}

	code := completeBody.Code
	var foundCode []models.EmailChange
	dataBase.DB.Model(models.EmailChange{}).Where("code = ?", code).Find(&foundCode)
	if len(foundCode) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Code not found", errorCodes.CodeNotFound))
		return
	} else if len(foundCode) > 1 {
		panic("duplicate data")
	}

	var users []models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", foundCode[0].UserID).Find(&users)
	if len(users) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "User not found", errorCodes.UsersNotFound))
		return
	} else if len(users) > 1 {
		panic("duplicate data")
	}

	var userRole []models.UserRole
	dataBase.DB.Model(models.UserRole{}).Where("id = ?", users[0].ID).Find(&userRole)
	if len(userRole) <= 0 {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "User role not found", errorCodes.RoleNotFound))
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

	tokens := models.AccessToken{
		UserId:       users[0].ID,
		AccessToken:  access,
		RefreshToken: refresh,
	}
	if err := dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", users[0].ID).Updates(tokens); err.Error != nil {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, "Error updating tokens", errorCodes.TokenUpdateError))
		return
	}

	response := models.EmailChangeResponse{
		Success:      true,
		Messages:     "Email changed",
		AccessToken:  access,
		RefreshToken: refresh,
	}

	c.JSON(http.StatusOK, response)
}
