package models

import "gorm.io/gorm"

type File struct {
	gorm.Model
	Filename string `gorm:"not null"`
	UUID     string `gorm:"unique;not null"`
}
