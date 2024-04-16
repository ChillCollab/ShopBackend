package dataBase

import (
	"backend_v1/models"
	"fmt"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

var DB *gorm.DB

func InitDB(cfg Config) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s", cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic(err)
	}

	if err := db.AutoMigrate(
		&models.User{},
		&models.UserRole{},
		&models.RegToken{},
		&models.UserPass{},
		&models.AccessToken{},
	); err != nil {
		panic(err)
	}

	fmt.Println("Migrate database")

	DB = db

}

func TimeNow() string {
	return time.Now().UTC().Format(os.Getenv("DATE_FORMAT"))
}
