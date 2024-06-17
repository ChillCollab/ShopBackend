package dataBase

import (
	"fmt"

	"backend/models"
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
	//Делай так во всех своих функциях
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

	//Нужно возвращать ошибку
	//И если она была при возврате, нужно отработать Rollback
	return tx.Commit().Error
}
