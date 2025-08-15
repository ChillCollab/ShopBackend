package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"backend/models/requestData"
	"backend/models/responses"
	"backend/pkg/authorization"
	"backend/pkg/client"

	"backend/internal/dataBase"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/language"
	"backend/pkg/utils"

	"github.com/gin-gonic/gin"
)

// CreateCategory создание категории
// @Summary Created product category
// @Description Endpoint to create product category
// @Tags Categories
// @Accept json
// @Produce json
// @Param body body requestData.CreateCategory true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/create [post]
func (a *App) CreateCategory(c *gin.Context) {
	lang := language.LangValue(c)
	token := authorization.GetToken(c)

	var categoryBody requestData.CreateCategory
	if err := c.ShouldBindJSON(&categoryBody); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}

	categoryCode, errGen := utils.LongCodeGen()
	if errGen != nil {
		a.logger.Error(errGen)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "error"), errorCodes.ServerError))
		return
	}
	userEmail := authorization.JwtParse(token).Email
	var foundUser models.User
	if err := a.db.Model(models.User{}).Where("email = ?", userEmail).First(&foundUser).Error; err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	category := models.Category{
		CategoryID:  categoryCode,
		Name:        categoryBody.Name,
		Image:       categoryBody.Image,
		Description: categoryBody.Description,
		CreatorID:   foundUser.ID,
		Created:     dataBase.TimeNow(),
		Updated:     dataBase.TimeNow(),
	}

	if err := a.db.Model(models.Category{}).Create(&category); err.Error != nil {
		a.logger.Error(err.Error)
		c.JSON(http.StatusInternalServerError, models.ResponseMsg(false, language.Language(lang, "error"), errorCodes.ServerError))
		return
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_created"), 0))

	// Attach action
	a.db.AttachAction(models.ActionLogs{
		Action:  "Create category: " + category.Name,
		Login:   foundUser.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})
}

// @Summary Get category info by id
// @Description Endpoint to get information about category by id
// @Tags Categories
// @Accept json
// @Produce json
// @Param category_id query string true "category id"
// @Success 200 object responses.CategoryInfo
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/info [get]
func (a *App) CategoryInfoById(c *gin.Context) {
	lang := language.LangValue(c)

	categoryId := c.Query("category_id")

	var foundCategory models.Category
	if err := a.db.Model(&models.Category{}).Where("category_id = ?", categoryId).First(&foundCategory); err.Error != nil {
		a.logger.Error(err.Error)
	}

	if foundCategory.CategoryID == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "category_not_found"), errorCodes.CategoryNotFound))
		return
	}

	c.JSON(http.StatusOK, responses.CategoryInfo{
		CategoryID:  foundCategory.CategoryID,
		Name:        foundCategory.Name,
		Image:       foundCategory.Image,
		Description: foundCategory.Description,
		CreatorID:   foundCategory.CreatorID,
		Created:     foundCategory.Created,
		Updated:     foundCategory.Updated,
	})
}

// @Summary Get categories list
// @Description Endpoint to get list of categories
// @Tags Categories
// @Accept json
// @Produce json
// @Success 200 object []responses.CategoryInfo
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/list [get]
func (a *App) GetCategoryList(c *gin.Context) {
	lang := language.LangValue(c)

	// Get all categories
	var foundCategories []models.Category
	if err := a.db.Model(&models.Category{}).Find(&foundCategories); err.Error != nil {
		a.logger.Error(err.Error)
	}

	if len(foundCategories) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "categories_list_empty"), errorCodes.CategoriesListEmpty))
		return
	}

	c.JSON(http.StatusOK, foundCategories)
}

// @Summary Update category
// @Description Endpoint to update category
// @Tags Categories
// @Accept json
// @Produce json
// @Param body body requestData.CategoryUpdate true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/update [patch]
func (a *App) CategoryUpdate(c *gin.Context) {
	lang := language.LangValue(c)

	var categoryBody requestData.CategoryUpdate
	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &categoryBody); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.UnmarshalError))
		return
	}

	// Get category
	var foundCategory models.Category
	if err := a.db.Model(&models.Category{}).Where("category_id = ?", categoryBody.CategoryID).First(&foundCategory); err.Error != nil {
		a.logger.Errorf("error get category: %v", err.Error)
	}

	if foundCategory.CategoryID == "" {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "category_not_found"), errorCodes.CategoryNotFound))
		return
	}

	// Update category
	newCategory := models.Category{
		Name:        utils.IfEmpty(categoryBody.Name, foundCategory.Name),
		Image:       utils.IfEmpty(categoryBody.Image, foundCategory.Image),
		Description: utils.IfEmpty(categoryBody.Description, foundCategory.Description),
		CategoryID:  foundCategory.CategoryID,
		CreatorID:   foundCategory.CreatorID,
		Created:     foundCategory.Created,
		Updated:     dataBase.TimeNow(),
	}

	if err := a.db.Model(&models.Category{}).Where("category_id = ?", categoryBody.CategoryID).Updates(&newCategory); err.Error != nil {
		a.logger.Errorf("error update category: %v", err.Error)
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "category_update_error"), errorCodes.CategoryUpdateError))
		return
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_updated"), 0))

	// Attach action
	token := authorization.GetToken(c)
	tokenData := authorization.JwtParse(token)
	fullUserInfo, errInfo := a.db.UserInfo(tokenData.Email, tokenData.Email)
	if errInfo != nil {
		a.logger.Errorf("error get user info: %v", errInfo)
	}

	a.db.AttachAction(models.ActionLogs{
		Action:  "Update category: " + foundCategory.Name,
		Login:   fullUserInfo.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})
}

// @Summary Delete category
// @Description Endpoint to delete category
// @Tags Categories
// @Accept json
// @Produce json
// @Param body body requestData.CategoryDelete true "request requestData"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/delete [delete]
func (a *App) DeleteCategory(c *gin.Context) {
	lang := language.LangValue(c)

	var categoryBody requestData.CategoryDelete
	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &categoryBody); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.UnmarshalError))
		return
	}

	// Get categories
	var foundCategories []models.Category
	if err := a.db.Model(&models.Category{}).Where("category_id = ?", categoryBody.CategoryID).Find(&foundCategories); err != nil {
		a.logger.Errorf("error get category: %v", err)
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "category_not_found"), errorCodes.CategoryNotFound))
		return
	}

	var categoryIDs []string
	for _, categoryId := range categoryBody.CategoryID {
		if categoryId == "" {
			a.logger.Error("Error deleting categories: category_id is empty")
			continue
		}
		categoryIDs = append(categoryIDs, categoryId)
	}

	tx := a.db.Begin()
	if err := tx.Where("category_id IN (?)", categoryIDs).Delete(&models.Category{}).Error; err != nil {
		tx.Rollback()
		a.logger.Error("Error deleting categories:", err)
	}
	tx.Commit()

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_deleted"), 0))

	// Attach action
	tokenData := authorization.JwtParse(c.GetHeader("Authorization"))
	fullUserInfo, errInfo := a.db.UserInfo(tokenData.Email, tokenData.Email)
	if errInfo != nil {
		a.logger.Errorf("error get user info: %v", errInfo)
	}

	var categoryNames []string
	for _, category := range foundCategories {
		categoryNames = append(categoryNames, category.Name)
	}

	a.db.AttachAction(models.ActionLogs{
		Action:  "Delete categories: " + strings.Join(categoryNames, ", "),
		Login:   fullUserInfo.Login,
		Ip:      client.GetIP(c),
		Created: dataBase.TimeNow(),
	})
}
