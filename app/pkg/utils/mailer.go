package utils

import (
	"backend/models"
	"backend/pkg/logger"
	"crypto/tls"
	"regexp"
	"strconv"

	gomail "gopkg.in/mail.v2"
	"gorm.io/gorm"
)

func MailValidator(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	match, _ := regexp.MatchString(emailRegex, email)
	return match
}

func Send(recipient string, subject string, msg string, db *gorm.DB) bool {
	log := logger.GetLogger()
	if !MailValidator(recipient) {
		log.Errorf("Validate mail error: Email " + recipient + " is not valid")
		return false
	}

	var host models.Config
	var port models.Config
	var email models.Config
	var password models.Config
	db.Model(&models.Config{}).Where("param = ?", "smtp_host").Find(&host)
	db.Model(&models.Config{}).Where("param = ?", "smtp_port").Find(&port)
	db.Model(&models.Config{}).Where("param = ?", "smtp_email").Find(&email)
	db.Model(&models.Config{}).Where("param = ?", "smtp_pass").Find(&password)

	if host.Value == "" || port.Value == "" || email.Value == "" || password.Value == "" {
		log.Error(host.Value, port.Value, email.Value, password.Value)
		log.Error("SMTP config not found or incorrect")
	}

	m := gomail.NewMessage()
	m.SetHeader("From", email.Value)

	m.SetHeader("To", recipient)

	m.SetHeader("Subject", subject)

	m.SetBody("text/plain", msg)

	prt, err := strconv.Atoi(port.Value)
	if err != nil {
		panic(err)
	}

	d := gomail.NewDialer(host.Value, prt, email.Value, password.Value)

	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		log.Error(err)
		return false
	}
	log.Info("Email was sent to: " + recipient)
	return true
}
