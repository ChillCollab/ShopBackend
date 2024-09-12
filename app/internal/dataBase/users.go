package dataBase

import (
	"errors"
	"fmt"
	"os"
	"time"

	"backend/models"
	"backend/models/requestData"
	"backend/pkg/logger"

	"gorm.io/gorm"
)

func (db *Database) UserInfo(login interface{}, email interface{}) (models.FullUserInfo, error) {
	var fullUserInfo models.FullUserInfo
	data := db.DB.
		Select(
			"users.id, users.login, users.name, users.surname, users.email, users.phone, users.role, users.active, users.pass, users.created, users.updated, users.avatar_id").
		Where("users.login = ? OR users.email = ?", login, email).
		First(&models.User{}).First(&fullUserInfo)

	if data.RowsAffected == 0 {
		return fullUserInfo, data.Error
	}

	return fullUserInfo, nil
}

func (db *Database) UserInfoById(id interface{}) (models.FullUserInfo, error) {
	var fullUserInfo models.FullUserInfo
	data := db.DB.
		Select(
			"users.id, users.login, users.name, users.surname, users.email, users.phone, users.role, users.active, users.pass, users.created, users.updated, users.avatar_id").
		Where("users.id = ?", id).
		First(&models.User{}).First(&fullUserInfo)

	if data.RowsAffected == 0 {
		return fullUserInfo, data.Error
	}

	return fullUserInfo, nil
}

func (db *Database) CreateUser(user models.User) error {
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	err := tx.Create(&user).Error
	if err != nil {
		return fmt.Errorf("error create user: %v", err)
	}
	return tx.Commit().Error
}

func (db *Database) CheckActivationCode(token models.RegToken) (tok models.RegToken, err error) {
	log := logger.GetLogger()
	tx := db.Begin()
	var activate models.RegToken
	codesRes := tx.Model(&models.RegToken{}).Where("code = ?", token.Code).First(&activate)
	if codesRes.RowsAffected <= 0 {
		log.Error("error get activation code")
		tx.Rollback()
		return activate, codesRes.Error
	}
	// Check if token is expired
	if activate.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		if deleteCode := tx.Model(&models.RegToken{}).Delete("code = ?", activate.Code); deleteCode.Error != nil {
			tx.Rollback()
			log.Error("error delete activation code")
			return activate, deleteCode.Error
		}
		log.Error("activation code expired")
		tx.Rollback()
		return activate, fmt.Errorf("activation code expired")
	}

	return activate, tx.Commit().Error
}

func (db *Database) CheckIfUserExist(login string, email string) bool {
	var user models.User
	if err := db.Model(&models.User{}).Where("login = ? OR email = ?", login, email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false
		}
		return false
	}
	return true
}

func (db *Database) UpdateUser(userData requestData.ChangeUser) error {
	if err := db.Model(&models.User{}).Where("id = ?", userData.ID).
		Updates(map[string]interface{}{
			"login":   userData.Login,
			"name":    userData.Name,
			"surname": userData.Surname,
			"email":   userData.Email,
			"phone":   userData.Phone,
			"role":    userData.Role,
			"active":  userData.Active,
		}).Error; err != nil {
		return err
	}

	return nil
}
