package dataBase

import (
	"backend/models"
	"backend/models/requestData"
)

func (db *Database) SmtpSet(data requestData.SmtpSettings) error {
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	settings := map[string]string{
		"smtp_host":     data.Host,
		"smtp_port":     data.Port,
		"smtp_email":    data.Email,
		"smtp_password": data.Password,
	}

	for param, value := range settings {
		if err := tx.Model(&models.Config{}).Where("param = ?", param).Updates(models.Config{
			Value:   value,
			Updated: TimeNow(),
		}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}
