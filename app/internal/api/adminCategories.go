package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"backend/models/requestData"
	"backend/models/responses"
	"backend/pkg/authorization"

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

	categoryCode := utils.LongCodeGen()
	userEmail := authorization.JwtParse(token).Email
	var foundUser models.User
	if err := a.db.Model(models.User{}).Where("email = ?", userEmail).First(&foundUser).Error; err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	category := models.Category{
		Name:       categoryBody.Name,
		CategoryID: categoryCode,
		CreatorID:  foundUser.ID,
		Created:    dataBase.TimeNow(),
		Updated:    dataBase.TimeNow(),
	}
	categoryDescription := models.CategoryDescription{
		CategoryID:  category.CategoryID,
		Description: categoryBody.Description,
		Created:     dataBase.TimeNow(),
		Updated:     dataBase.TimeNow(),
	}
	categoryImage := models.CategoryImage{
		CategoryID: category.CategoryID,
		Image:      categoryBody.Image,
		Created:    dataBase.TimeNow(),
		Updated:    dataBase.TimeNow(),
	}

	//ошибки
	a.db.Model(models.Category{}).Create(&category)
	a.db.Model(models.CategoryDescription{}).Create(&categoryDescription)
	a.db.Model(models.CategoryImage{}).Create(&categoryImage)

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_created"), 0))

	// Attach action
	a.db.AttachAction(models.ActionLogs{
		Action:  "Create category: " + category.Name,
		Login:   foundUser.Login,
		Ip:      c.ClientIP(),
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
	if err := a.db.Model(&models.Category{}).Where("category_id = ?", categoryId).First(&foundCategory); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "category_not_found"), errorCodes.CategoryNotFound))
		return
	}

	var foundCategoryDescription models.CategoryDescription
	var foundCategoryImage models.CategoryImage
	if err := a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryId).First(&foundCategoryDescription); err != nil {
		a.logger.Logger.Errorf("error get category description: %v", err)
	}

	if err := a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryId).First(&foundCategoryImage); err != nil {
		a.logger.Logger.Infof("error get category image: %v", err)
	}

	c.JSON(http.StatusOK, responses.CategoryInfo{
		CategoryID:  foundCategory.CategoryID,
		Name:        foundCategory.Name,
		Image:       foundCategoryImage.Image,
		Description: foundCategoryDescription.Description,
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
	a.db.Model(&models.Category{}).Find(&foundCategories)

	if len(foundCategories) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "categories_list_empty"), errorCodes.CategoriesListEmpty))
		return
	}

	// Collecting all categories
	var categoryList []responses.CategoryInfo
	// И когда у тебя будет 100 категорий, ты сделаешь 200 запросов в БД
	for _, category := range foundCategories {
		var foundCategoryDescription models.CategoryDescription
		var foundCategoryImage models.CategoryImage
		if err := a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", category.CategoryID).First(&foundCategoryDescription); err != nil {
			a.logger.Errorf("error get category description: %v", category.Name)
		}

		if err := a.db.Model(&models.CategoryImage{}).Where("category_id = ?", category.CategoryID).First(&foundCategoryImage); err != nil {
			a.logger.Errorf("error get category image: %v", category.Name)
		}

		categoryList = append(categoryList, responses.CategoryInfo{
			CategoryID:  category.CategoryID,
			Name:        category.Name,
			Image:       foundCategoryImage.Image,
			Description: foundCategoryDescription.Description,
			CreatorID:   category.CreatorID,
			Created:     category.Created,
			Updated:     category.Updated,
		})
	}

	c.JSON(http.StatusOK, categoryList)
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
	if err := a.db.Model(&models.Category{}).Where("category_id = ?", categoryBody.CategoryID).First(&foundCategory); err != nil {
		a.logger.Errorf("error get category: %v", err)
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "category_not_found"), errorCodes.CategoryNotFound))
		return
	}

	// Get category description and image
	var foundCategoryDescription models.CategoryDescription
	var foundCategoryImage models.CategoryImage
	if err := a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryBody.CategoryID).First(&foundCategoryDescription); err != nil {
		a.logger.Errorf("error get category description: %v", err)
	}
	if err := a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryBody.CategoryID).Find(&foundCategoryImage); err != nil {
		a.logger.Errorf("error get category image: %v", err)
	}

	// Update category
	newCategory := models.Category{
		Name:       utils.IfEmpty(categoryBody.Name, foundCategory.Name),
		CategoryID: foundCategory.CategoryID,
		CreatorID:  foundCategory.CreatorID,
		Created:    foundCategory.Created,
		Updated:    dataBase.TimeNow(),
	}
	newCategoryDescription := models.CategoryDescription{
		CategoryID:  foundCategoryDescription.CategoryID,
		Description: utils.IfEmpty(categoryBody.Description, foundCategoryDescription.Description),
		Created:     foundCategoryDescription.Created,
		Updated:     dataBase.TimeNow(),
	}
	newCategoryImage := models.CategoryImage{
		CategoryID: foundCategoryImage.CategoryID,
		Image:      utils.IfEmpty(categoryBody.Image, foundCategoryImage.Image),
		Created:    foundCategoryImage.Created,
		Updated:    dataBase.TimeNow(),
	}
	//ошибки
	a.db.Model(&models.Category{}).Where("category_id = ?", categoryBody.CategoryID).Updates(&newCategory)
	a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryBody.CategoryID).Updates(&newCategoryDescription)
	a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryBody.CategoryID).Updates(&newCategoryImage)

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_updated"), 0))

	// Attach action
	tokenData := authorization.JwtParse(c.GetHeader("Authorization"))
	fullUserInfo, errInfo := a.db.UserInfo(tokenData.Email, tokenData.Email)
	if errInfo != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	a.db.AttachAction(models.ActionLogs{
		Action:  "Update category: " + foundCategory.Name,
		Login:   fullUserInfo.Login,
		Ip:      c.ClientIP(),
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

	var categoryNames []string
	for _, category := range foundCategories {
		categoryNames = append(categoryNames, category.Name)
	}

	//Обернуть в транзацкию и вынести отдельно
	//Ошибки
	// Delete category
	a.db.Model(&models.Category{}).Where("category_id = ?", categoryBody.CategoryID).Delete(&models.Category{})
	a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryBody.CategoryID).Delete(&models.CategoryDescription{})
	a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryBody.CategoryID).Delete(&models.CategoryImage{})

	for _, categoryId := range categoryBody.CategoryID {
		//Ошибки
		a.db.Model(&models.Category{}).Where("category_id = ?", categoryId).Delete(&models.Category{})
		a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryId).Delete(&models.CategoryDescription{})
		a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryId).Delete(&models.CategoryImage{})
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_deleted"), 0))

	// Attach action
	tokenData := authorization.JwtParse(c.GetHeader("Authorization"))
	fullUserInfo, errInfo := a.db.UserInfo(tokenData.Email, tokenData.Email)
	if errInfo != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	a.db.AttachAction(models.ActionLogs{
		Action:  "Delete categories: " + strings.Join(categoryNames, ", "),
		Login:   fullUserInfo.Login,
		Ip:      c.ClientIP(),
		Created: dataBase.TimeNow(),
	})
}
