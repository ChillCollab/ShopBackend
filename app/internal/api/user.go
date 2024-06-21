package api

import (
	"backend/internal/dataBase"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/models/requestData"
	"backend/models/responses"
	"backend/pkg/authorization"
	"backend/pkg/client"
	"backend/pkg/images"
	"backend/pkg/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gorm.io/gorm"

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

	digits, symbol := utils.PasswordChecker(passwordData.NewPassword)
	if !digits && !symbol {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "password_should_be_include_digits"), errorCodes.PasswordShouldByIncludeSymbols))
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
	a.db.AttachAction(models.ActionLogs{
		Action:  "Change password",
		Login:   fullUserInfo.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})
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

	var users models.User
	if err := a.db.Model(models.User{}).Where("email = ?", email).First(&users); err.Error != nil {
		a.logger.Errorf("error get user: %v", err.Error)
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
		var checkLogin models.User
		if err := a.db.Model(models.User{}).Where("login = ?", user.Login).Where("id != ?", users.ID).First(&checkLogin); err.Error != nil {
			a.logger.Errorf("error get user: %v", err.Error)
		}
		if checkLogin.ID != 0 {
			c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "login_already_exist"), errorCodes.LoginAlreadyExist))
			return
		}
	}

	newData := models.User{
		Login:   utils.IfEmpty(user.Login, users.Login),
		Name:    utils.IfEmpty(user.Name, users.Name),
		Surname: utils.IfEmpty(user.Surname, users.Surname),
		Phone:   utils.IfEmpty(user.Phone, users.Phone),
		Active:  users.Active,
		Email:   users.Email,
		Created: users.Created,
		Updated: dataBase.TimeNow(),
	}

	a.db.Model(models.User{}).Where("email = ?", email).Updates(newData)

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "user_data_updated"), 0))

	a.db.AttachAction(models.ActionLogs{
		Action:  "Change personal data",
		Login:   users.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})

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
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

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

	a.db.AttachAction(models.ActionLogs{
		Action:  "Try to change email",
		Login:   user.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})
}

// ChangeEmailComplete Поздтверждение смены email
// @Summary Change email complete
// @Description Endpoint to complete email change
// @Tags User
// @Accept json
// @Produce json
// @Param body body requestData.ChangeEmailComplete true "request requestData"
// @Success 200 object responses.ChangeEmail
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /user/change/email/submit [patch]
func (a *App) ChangeEmailComplete(c *gin.Context) {
	lang := language.LangValue(c)
	var completeBody requestData.ChangeEmailComplete

	if err := c.ShouldBindJSON(&completeBody); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	tx := a.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	code := completeBody.Code
	var foundCode models.EmailChange
	if err := tx.Model(models.EmailChange{}).Where("code = ?", code).First(&foundCode).Error; err != nil {
		a.logger.Infof("error get email change code: %v", err)
	}
	if foundCode.Code == 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "code_not_found"), errorCodes.CodeNotFound))
		return
	}

	var users models.User
	if err := tx.Model(models.User{}).Where("id = ?", foundCode.UserID).First(&users).Error; err != nil {
		a.logger.Infof("error get user: %v", err)
	}
	if users.ID == 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UsersNotFound))
		return
	}

	if err := tx.Model(models.User{}).Where("id = ?", foundCode.UserID).Update("email", foundCode.Email); err.Error != nil {
		a.logger.Infof("error update email: %v", err)
		tx.Rollback()
	}
	if err := tx.Model(models.User{}).Where("id = ?", foundCode.UserID).Update("updated", dataBase.TimeNow()); err.Error != nil {
		a.logger.Infof("error update email: %v", err)
		tx.Rollback()
	}
	if err := tx.Model(models.EmailChange{}).Where("code = ?", code).Delete(&foundCode); err.Error != nil {
		a.logger.Infof("error delete email change code: %v", err)
		tx.Rollback()
	}

	tx.Commit()

	access, refresh, err := authorization.GenerateJWT(authorization.TokenData{
		Authorized: true,
		Email:      foundCode.Email,
		Role:       users.RoleId,
	})
	if err != nil {
		a.logger.Errorf("error generate token: %v", err)
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

	response := responses.ChangeEmail{
		Success:      true,
		Messages:     language.Language(lang, "email_updated"),
		AccessToken:  access,
		RefreshToken: refresh,
	}

	c.JSON(http.StatusOK, response)

	a.db.AttachAction(models.ActionLogs{
		Action:  "Change email complete",
		Login:   users.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})
}

// UploadAvatar загрузка аватара для пользователя
// @Summary Upload avatar
// @Description Upload avatar
// @Tags User
// @Accept */*
// @Produce multipart/form-data
// @Param file formData file true "File to upload"
// @Success 200 {object} string
// @Failure 400 {object} string
// @Failure 401 {object} string
// @Failure 500 {object} string
// @Security ApiKeyAuth
// @Router /user/upload/avatar [post]
func (a *App) UploadAvatar(c *gin.Context) {
	lang := language.LangValue(c)

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
	result := a.db.Model(models.User{}).Where("email = ?", email).Find(&users)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, "internal error", errorCodes.DBError))
		return
	}

	if len(users) == 0 {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	if len(users) > 1 {
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{language.Language(lang, "error"): err.Error()})
		return
	}

	maxFileSize := 1024 * 3072
	if file.Size > int64(maxFileSize) {
		c.JSON(
			http.StatusBadRequest,
			models.ResponseMsg(false, language.Language(lang, "too_big_avatar_size"), errorCodes.AvatarSizelimit),
		)
		return
	}

	allowedExtensions := []string{".jpg", ".jpeg", ".png"}
	ext := strings.ToLower(filepath.Ext(file.Filename))
	validExtension := false
	for _, allowedExt := range allowedExtensions {
		if ext == allowedExt {
			validExtension = true
			break
		}
	}

	if !validExtension {
		c.JSON(http.StatusBadRequest, gin.H{language.Language(lang, "error"): language.Language(lang, "unsupported_file_extension")})
		return
	}

	uuid, errGen := utils.LongCodeGen()
	if errGen != nil {
		a.logger.Errorf("error generate uuid: %v", errGen)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate UUID"})
	}

	filePath := filepath.Join(os.Getenv("IMAGES_PATH"), file.Filename)
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	if users[0].AvatarId != "" {
		var foundImages models.File

		if err := a.db.Model(&models.File{}).Where("uuid = ?", users[0].AvatarId).First(&foundImages); err.Error != nil {
			a.logger.Errorf("error create avatar: %v", err)
		}

		if foundImages.Filename != "" {
			oldFilePath := filepath.Join(os.Getenv("IMAGES_PATH"), foundImages.Filename)
			err = os.Remove(oldFilePath)
			if err != nil {
				a.logger.Errorf("error create avatar: %v", err)
			}
			a.db.Model(&models.File{}).Where("uuid = ?", users[0].AvatarId).Delete(&models.File{})
		}
	}

	fileMetadata := models.File{
		Filename: file.Filename,
		UUID:     uuid,
	}
	if err := a.db.Create(&fileMetadata).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file metadata"})
		return
	}

	result = a.db.Model(&models.User{}).Where("email = ?", email).Update("avatar_id", uuid)
	if result.Error != nil {
		a.logger.Errorf("error update avatar: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update avatar"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "Details": fileMetadata})
}

// GetAvatar получить аватар пользователяadas
// @Summary Get avatar by uuid
// @Description Get avatar by uuid
// @Tags User
// @Accept json
// @Produce json
// @Param uuid path string true "UUID of the avatar"
// @Success 200 {object} string
// @Failure 400 {object} string
// @Failure 404 {object} string
// @Failure 500 {object} string
// @Router /user/avatar/{uuid} [get]
func (a *App) GetAvatar(ctx *gin.Context) {
	uuid := ctx.Param("uuid")

	var file models.File

	err := a.db.Where("uuid = ?", uuid).First(&file).Error
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Define the path of the file to be retrieved
	filePath := filepath.Join(os.Getenv("IMAGES_PATH"), file.Filename)
	// Open the file
	fileData, err := os.Open(filePath)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}
	defer func(fileData *os.File) {
		err := fileData.Close()
		if err != nil {

		}
	}(fileData)
	// Read the first 512 bytes of the file to determine its content type
	fileHeader := make([]byte, 512)
	_, err = fileData.Read(fileHeader)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}
	fileContentType := http.DetectContentType(fileHeader)
	// Get the file info
	fileInfo, err := fileData.Stat()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get file info"})
		return
	}
	// Set the headers for the file transfer and return the file
	ctx.Header("Content-Description", "File Transfer")
	ctx.Header("Content-Transfer-Encoding", "binary")
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file.Filename))
	ctx.Header("Content-Type", fileContentType)
	ctx.Header("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	ctx.File(filePath)
}

func DeleteFile(ctx *gin.Context, db *gorm.DB) {

	uuid := ctx.Param("uuid")
	var file models.File
	// Retrieve the file metadata from the database
	err := db.Where("uuid = ?", uuid).First(&file).Error
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	// Define the path of the file to be deleted
	filePath := filepath.Join("uploads", file.Filename)
	// Delete the file from the server
	err = os.Remove(filePath)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete file from upload folder"})
		return
	}
	// Delete the file metadata from the database
	err = db.Delete(&file).Error
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete file from database"})
		return
	}
	// Return a success message
	ctx.JSON(http.StatusOK, gin.H{
		"message": "File " + file.Filename + " deleted successfully",
	})
}
