package db

import (
	dataBase "backend/internal/dataBase/models"
	"backend/models"
)

func UserInfo(login string) (models.FullUserInfo, models.AccessToken, error) {
	var fullUserInfo models.FullUserInfo

	data := dataBase.DB.
		Select(
			"users.id, users.login, users.name, users.surname, users.email, users.phone, user_roles.role, users.active, user_passes.pass, users.created, users.updated, users.avatar_id, user_roles.role").
		Joins("JOIN user_roles ON users.id = user_roles.id").
		Joins("JOIN user_passes ON users.id = user_passes.user_id").
		Where("users.login = ?", login).
		First(&models.User{}).First(&fullUserInfo)

	if data.RowsAffected == 0 {
		return fullUserInfo, models.AccessToken{}, data.Error
	}
	var tokens models.AccessToken
	err := dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", fullUserInfo.ID).First(&tokens).Error
	if err != nil {
		tokens.AccessToken = ""
		tokens.RefreshToken = ""
		return fullUserInfo, tokens, nil
	}

	return fullUserInfo, tokens, nil
}
