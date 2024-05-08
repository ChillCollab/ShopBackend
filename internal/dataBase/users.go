package dataBase

import "backend/models"

func (db *Database) UserInfo(login string) (models.FullUserInfo, error) {
	var fullUserInfo models.FullUserInfo

	data := db.DB.
		Select(
			"users.id, users.login, users.name, users.surname, users.email, users.phone, user_roles.role, users.active, user_passes.pass, users.created, users.updated, users.avatar_id, user_roles.role").
		Joins("JOIN user_roles ON users.id = user_roles.id").
		Joins("JOIN user_passes ON users.id = user_passes.user_id").
		Where("users.login = ?", login).
		First(&models.User{}).First(&fullUserInfo)

	if data.RowsAffected == 0 {
		return fullUserInfo, data.Error
	}

	return fullUserInfo, nil
}
