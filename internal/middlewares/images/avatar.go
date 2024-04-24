package images

import (
	dataBase "backend/internal/dataBase/models"
	"backend/models"
	"backend/pkg/utils"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type FileController struct {
	DB *gorm.DB
}

func AvatarUrl(imageId string) string {
	return fmt.Sprintf(os.Getenv("DOMAIN")+":"+os.Getenv("APP_PORT")+"/api_v1/user/avatar/%s", imageId)
}

func UploadFiles(ctx *gin.Context) {

	form, err := ctx.MultipartForm()
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	files := form.File["files"]
	var fileModels []models.File

	for _, file := range files {
		filePath := filepath.Join("uploads", file.Filename)
		if err := ctx.SaveUploadedFile(file, filePath); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
			return
		}
		fileModels = append(fileModels, models.File{
			UUID:     utils.LongCodeGen(),
			Filename: file.Filename,
		})
	}

	err = dataBase.DB.Create(&fileModels).Error
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file information"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "File uploaded successfully",
		"files":   fileModels,
	})
}

func DeleteFile(ctx *gin.Context) {

	uuid := ctx.Param("uuid")
	var file models.File
	// Retrieve the file metadata from the database
	err := dataBase.DB.Where("uuid = ?", uuid).First(&file).Error
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
	err = dataBase.DB.Delete(&file).Error
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete file from database"})
		return
	}
	// Return a success message
	ctx.JSON(http.StatusOK, gin.H{
		"message": "File " + file.Filename + " deleted successfully",
	})
}
