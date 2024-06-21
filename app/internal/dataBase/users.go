package dataBase

import (
	"fmt"
	"os"
	"time"

	"backend/models"
	"backend/pkg/logger"
)

func (db *Database) UserInfo(login interface{}, email interface{}) (models.FullUserInfo, error) {
	var fullUserInfo models.FullUserInfo
	data := db.DB.
		Select(
			"users.id, users.login, users.name, users.surname, users.email, users.phone, users.role_id, users.active, users.pass, users.created, users.updated, users.avatar_id").
		Where("users.login = ? OR users.email = ?", login, email).
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

func (db *Database) CheckActivationCode(token models.RegToken) error {
	log := logger.GetLogger()
	tx := db.Begin()
	var activate models.RegToken
	codesRes := tx.Model(&models.RegToken{}).Where("code = ?", token.Code).First(&activate)
	if codesRes.RowsAffected <= 0 {
		log.Error("error get activation code")
		tx.Rollback()
		return codesRes.Error
	}
	// Check if token is expired
	if activate.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		if deleteCode := tx.Model(&models.RegToken{}).Delete("code = ?", activate.Code); deleteCode.Error != nil {
			tx.Rollback()
			log.Error("error delete activation code")
			return deleteCode.Error
		}
		log.Error("activation code expired")
		tx.Rollback()
		return fmt.Errorf("activation code expired")
	}

	return tx.Commit().Error
}
