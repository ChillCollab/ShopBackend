package dataBase

import (
	"backend/models"
	"backend/pkg/logger"
)

func (db *Database) AttachAction(logs models.ActionLogs) {
	log := logger.GetLogger()
	tx := db.Begin()
	if err := tx.Create(&logs).Error; err != nil {
		log.Errorf("error create action log: %v", err)
	}
	tx.Commit()
}

func (db *Database) GetActionLogs() []models.ActionLogs {
	var logs []models.ActionLogs
	db.Find(&logs)
	return logs
}
