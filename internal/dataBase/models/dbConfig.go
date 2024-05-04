package dataBase

import (
	"backend/models"
	"backend/pkg/logger"
	"backend/pkg/utils"
	"fmt"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type dbConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

var DB *gorm.DB

func InitDB() error {

	logger := logger.GetLogger()

	cfg := dbConfig{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s", cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		return err
	}

	if err := db.AutoMigrate(
		&models.Config{},
		&models.User{},
		&models.File{},
		&models.UserRole{},
		&models.RegToken{},
		&models.UserPass{},
		&models.AccessToken{},
		&models.EmailChange{},
		&models.Category{},
		&models.CategoryDescription{},
		&models.CategoryImage{},
	); err != nil {
		return err
	}

	createConfig(db)
	createDefaultUserIfNotExists(db)

	logger.Info("Database migrated successfully")

	DB = db
	return nil
}

func createConfig(db *gorm.DB) {
	var count int64
	db.Model(&models.Config{}).Where("param = ?", "smtp_host").Count(&count)
	if count == 0 {
		db.Model(&models.Config{}).Create(&models.Config{
			Param:    "smtp_host",
			Value:    "",
			Activate: true,
			Updated:  TimeNow(),
		})
	}
	db.Model(&models.Config{}).Where("param = ?", "smtp_port").Count(&count)
	if count == 0 {
		db.Model(&models.Config{}).Create(&models.Config{
			Param:    "smtp_port",
			Value:    "",
			Activate: true,
			Updated:  TimeNow(),
		})
	}
	db.Model(&models.Config{}).Where("param = ?", "smtp_email").Count(&count)
	if count == 0 {
		db.Model(&models.Config{}).Create(&models.Config{
			Param:    "smtp_email",
			Value:    "",
			Activate: true,
			Updated:  TimeNow(),
		})
	}
	db.Model(&models.Config{}).Where("param = ?", "smtp_pass").Count(&count)
	if count == 0 {
		db.Model(&models.Config{}).Create(&models.Config{
			Param:    "smtp_pass",
			Value:    "",
			Activate: true,
			Updated:  TimeNow(),
		})
	}
}

func createDefaultUserIfNotExists(db *gorm.DB) {
	var count int64
	if err := db.Model(&models.User{}).Where("login = ?", "universal").Count(&count).Error; err != nil {
		panic(err)
	}
	if count == 0 {
		defaultUser := models.User{
			ID:      uint(0),
			Login:   "universal",
			Name:    "Main",
			Surname: "Admin",
			Email:   "uni@example.com",
			Phone:   "00000000000",
			Active:  true,
			Created: TimeNow(),
			Updated: TimeNow(),
		}
		if err := db.Create(&defaultUser).Error; err != nil {
			panic(err)
		}

		var user models.User
		db.Model(&models.User{}).Where("login = ?", "universal").First(&user)
		db.Model(&models.UserPass{}).Create(models.UserPass{
			UserId:  user.ID,
			Pass:    utils.Hash("admin"),
			Updated: TimeNow(),
		})
		db.Model(&models.UserRole{}).Create(&models.UserRole{
			ID:      user.ID,
			Role:    1,
			Updated: TimeNow(),
		})
	}
}

func TimeNow() string {
	return time.Now().UTC().Format(os.Getenv("DATE_FORMAT"))
}
