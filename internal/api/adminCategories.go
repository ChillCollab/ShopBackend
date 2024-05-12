package api

import (
	"backend/internal/api/middlewares"
	"encoding/json"
	"fmt"
	"net/http"

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
// @Param body body models.CategoryCreateBody true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/create [post]
func (a *App) CreateCategory(c *gin.Context) {
	var categoryBody models.CategoryCreateBody
	lang := language.LangValue(c)
	token := middlewares.GetToken(c)
	if token == "" {
		c.JSON(
			http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	if !middlewares.CheckAdmin(token) {
		c.JSON(http.StatusUnauthorized,
			models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized),
		)
		return
	}

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(
			http.StatusBadRequest,
			models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError),
		)
		return
	}

	if err := json.Unmarshal(rawData, &categoryBody); err != nil {
		c.JSON(
			http.StatusBadRequest,
			models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.UnmarshalError),
		)
		return
	}

	categoryCode := utils.LongCodeGen()
	userEmail := middlewares.JwtParse(token).Email
	var foundUser []models.User
	a.db.Model(models.User{}).Where("email = ?", userEmail).Find(&foundUser)
	if len(foundUser) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "inc"), errorCodes.Unauthorized))
		return
	} else if len(foundUser) > 1 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}

	category := models.Category{
		Name:       categoryBody.Name,
		CategoryID: categoryCode,
		CreatorID:  foundUser[0].ID,
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

	a.db.Model(models.Category{}).Create(&category)
	a.db.Model(models.CategoryDescription{}).Create(&categoryDescription)
	a.db.Model(models.CategoryImage{}).Create(&categoryImage)

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_created"), 0))
}

// @Summary Get category info by id
// @Description Endpoint to get information about category by id
// @Tags Categories
// @Accept json
// @Produce json
// @Param category_id query string true "category id"
// @Success 200 object models.CategoryInfo
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/info [get]
func (a *App) CategoryInfoById(c *gin.Context) {
	lang := language.LangValue(c)
	token := middlewares.GetToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	if !middlewares.CheckAdmin(token) {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	categoryId := c.Query("category_id")

	var foundCategory []models.Category
	a.db.Model(&models.Category{}).Where("category_id = ?", categoryId).Find(&foundCategory)
	if len(foundCategory) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "category_not_found"), errorCodes.CategoryNotFound))
		return
	} else if len(foundCategory) > 1 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}
	var foundCategoryDescription []models.CategoryDescription
	var foundCategoryImage []models.CategoryImage
	a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryId).Find(&foundCategoryDescription)
	if len(foundCategoryDescription) <= 0 {
		panic(fmt.Errorf("category description not found"))
	} else if len(foundCategoryDescription) > 1 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}
	a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryId).Find(&foundCategoryImage)
	if len(foundCategoryImage) <= 0 {
		panic(fmt.Errorf("category image not found"))
	} else if len(foundCategoryImage) > 1 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}

	c.JSON(http.StatusOK, models.CategoryInfo{
		CategoryID:  foundCategory[0].CategoryID,
		Name:        foundCategory[0].Name,
		Image:       foundCategoryImage[0].Image,
		Description: foundCategoryDescription[0].Description,
		CreatorID:   foundCategory[0].CreatorID,
		Created:     foundCategory[0].Created,
		Updated:     foundCategory[0].Updated,
	})
}

// @Summary Get categories list
// @Description Endpoint to get list of categories
// @Tags Categories
// @Accept json
// @Produce json
// @Success 200 object []models.CategoryInfo
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/list [get]
func (a *App) GetCategoryList(c *gin.Context) {
	lang := language.LangValue(c)
	token := middlewares.GetToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	if !middlewares.CheckAdmin(token) {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	var foundCategories []models.Category
	a.db.Model(&models.Category{}).Find(&foundCategories)

	if len(foundCategories) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "categories_list_empty"), errorCodes.CategoriesListEmpty))
		return
	}

	var categoryList []models.CategoryInfo
	for _, category := range foundCategories {
		var foundCategoryDescription []models.CategoryDescription
		var foundCategoryImage []models.CategoryImage
		a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", category.CategoryID).Find(&foundCategoryDescription)
		if len(foundCategoryDescription) <= 0 {
			panic(fmt.Errorf("category description not found"))
		} else if len(foundCategoryDescription) > 1 {
			c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
			return
		}
		a.db.Model(&models.CategoryImage{}).Where("category_id = ?", category.CategoryID).Find(&foundCategoryImage)
		if len(foundCategoryImage) <= 0 {
			panic(fmt.Errorf("category image not found"))
		} else if len(foundCategoryImage) > 1 {
			c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
			return
		}

		categoryList = append(categoryList, models.CategoryInfo{
			CategoryID:  category.CategoryID,
			Name:        category.Name,
			Image:       foundCategoryImage[0].Image,
			Description: foundCategoryDescription[0].Description,
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
// @Param body body models.CategoryUpdateBody true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/update [patch]
func (a *App) CategoryUpdate(c *gin.Context) {
	lang := language.LangValue(c)
	token := middlewares.GetToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	if !middlewares.CheckAdmin(token) {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	var categoryBody models.CategoryUpdateBody
	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &categoryBody); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.UnmarshalError))
		return
	}

	var foundCategory []models.Category
	a.db.Model(&models.Category{}).Where("category_id = ?", categoryBody.CategoryID).Find(&foundCategory)
	if len(foundCategory) <= 0 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "category_not_found"), errorCodes.CategoryNotFound))
		return
	} else if len(foundCategory) > 1 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}

	var foundCategoryDescription []models.CategoryDescription
	var foundCategoryImage []models.CategoryImage
	a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryBody.CategoryID).Find(&foundCategoryDescription)
	if len(foundCategoryDescription) <= 0 {
		panic(fmt.Errorf("category description not found"))
	} else if len(foundCategoryDescription) > 1 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}
	a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryBody.CategoryID).Find(&foundCategoryImage)
	if len(foundCategoryImage) <= 0 {
		panic(fmt.Errorf("category image not found"))
	} else if len(foundCategoryImage) > 1 {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData))
		return
	}

	newCategory := models.Category{
		Name:       utils.IfEmpty(categoryBody.Name, foundCategory[0].Name),
		CategoryID: foundCategory[0].CategoryID,
		CreatorID:  foundCategory[0].CreatorID,
		Created:    foundCategory[0].Created,
		Updated:    dataBase.TimeNow(),
	}
	newCategoryDescription := models.CategoryDescription{
		CategoryID:  foundCategoryDescription[0].CategoryID,
		Description: utils.IfEmpty(categoryBody.Description, foundCategoryDescription[0].Description),
		Created:     foundCategoryDescription[0].Created,
		Updated:     dataBase.TimeNow(),
	}
	newCategoryImage := models.CategoryImage{
		CategoryID: foundCategoryImage[0].CategoryID,
		Image:      utils.IfEmpty(categoryBody.Image, foundCategoryImage[0].Image),
		Created:    foundCategoryImage[0].Created,
		Updated:    dataBase.TimeNow(),
	}
	a.db.Model(&models.Category{}).Where("category_id = ?", categoryBody.CategoryID).Updates(&newCategory)
	a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryBody.CategoryID).Updates(&newCategoryDescription)
	a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryBody.CategoryID).Updates(&newCategoryImage)

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_updated"), 0))
}

// @Summary Delete category
// @Description Endpoint to delete category
// @Tags Categories
// @Accept json
// @Produce json
// @Param body body models.CategoryDeleteBody true "request body"
// @Success 200 object models.SuccessResponse
// @Failure 400 object models.ErrorResponse
// @Failure 401 object models.ErrorResponse
// @Failure 500
// @Security ApiKeyAuth
// @Router /admin/categories/delete [delete]
func (a *App) DeleteCategory(c *gin.Context) {
	lang := language.LangValue(c)
	token := middlewares.GetToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}
	if !middlewares.CheckAdmin(token) {
		c.JSON(http.StatusUnauthorized, models.ResponseMsg(false, language.Language(lang, "incorrect_email_or_password"), errorCodes.Unauthorized))
		return
	}

	var categoryBody models.CategoryDeleteBody
	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "parse_error"), errorCodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &categoryBody); err != nil {
		c.JSON(http.StatusBadRequest, models.ResponseMsg(false, language.Language(lang, "unmarshal_error"), errorCodes.UnmarshalError))
		return
	}

	for _, categoryId := range categoryBody.CategoryID {
		a.db.Model(&models.Category{}).Where("category_id = ?", categoryId).Delete(&models.Category{})
		a.db.Model(&models.CategoryDescription{}).Where("category_id = ?", categoryId).Delete(&models.CategoryDescription{})
		a.db.Model(&models.CategoryImage{}).Where("category_id = ?", categoryId).Delete(&models.CategoryImage{})
	}

	c.JSON(http.StatusOK, models.ResponseMsg(true, language.Language(lang, "category_deleted"), 0))
}
