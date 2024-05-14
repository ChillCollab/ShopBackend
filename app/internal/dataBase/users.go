package dataBase

import (
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

func (db *Database) CreateUser(user models.User) (err error) {
	tx := db.Begin()

	create := tx.Create(&user)
	if create.Error != nil {
		tx.Rollback()
		return create.Error
	}

	tx.Commit()

	return nil
}