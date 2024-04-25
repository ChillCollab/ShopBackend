package userController

import (
	dataBase "backend/internal/dataBase/models"
	"backend/internal/errorCodes"
	"backend/internal/middlewares/auth"
	"backend/internal/middlewares/handlers"
	"backend/internal/middlewares/language"
	"backend/models"
	"backend/pkg/utils"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

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
func UploadAvatar(c *gin.Context) {
	lang := language.LangValue(c)

	token := auth.CheckAuth(c, true)
	if token == "" {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	email := auth.JwtParse(token).Email
	var users []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", email).Find(&users)
	if len(users) == 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	} else if len(users) > 1 {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{language.Language(lang, "error"): err.Error()})
		return
	}

	maxFileSize := 1024 * 3072

	if file.Size > int64(maxFileSize) {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, language.Language(lang, "too_big_avatar_size"), errorCodes.AvatarSizelimit))
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

	uuid := utils.LongCodeGen()
	if users[0].AvatarId != "" {
		var foundImages []models.File
		dataBase.DB.Model(&models.File{}).Where("uuid = ?", users[0].AvatarId).Find(&foundImages)
		if len(foundImages) != 0 {
			oldFilePath := filepath.Join(os.Getenv("IMAGES_PATH"), foundImages[0].Filename)
			err = os.Remove(oldFilePath)
			if err != nil {
				fmt.Println(language.Language(lang, "error"), err.Error())
			}
			dataBase.DB.Model(&models.File{}).Where("uuid = ?", users[0].AvatarId).Delete(&models.File{})
		} else if len(foundImages) > 1 {
			c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
			return
		}
	}

	filePath := filepath.Join(os.Getenv("IMAGES_PATH"), file.Filename)

	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	fileMetadata := models.File{
		Filename: file.Filename,
		UUID:     uuid,
	}
	if err := dataBase.DB.Create(&fileMetadata).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file metadata"})
		return
	}

	dataBase.DB.Model(&models.User{}).Where("email = ?", email).Update("avatar_id", uuid)

	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "Details": fileMetadata})
}

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
func GetAvatar(ctx *gin.Context) {

	uuid := ctx.Param("uuid")

	fmt.Println(uuid)
	var file models.File

	err := dataBase.DB.Where("uuid = ?", uuid).First(&file).Error
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
	defer fileData.Close()
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
