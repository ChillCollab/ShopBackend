package consumer

import (
	"backend/consumer/template"
	"backend/models"
	"backend/pkg/logger"
	"backend/pkg/utils"
	"crypto/tls"
	"strconv"

	gomail "gopkg.in/mail.v2"
	"gorm.io/gorm"
)

func Send(recipient string, subject string, msg string, db *gorm.DB) bool {
	log := logger.GetLogger()
	if !utils.MailValidator(recipient) {
		log.Errorf("Validate mail error: Email " + recipient + " is not valid")
		return false
	}

	var configs []models.Config
	params := []string{"smtp_host", "smtp_port", "smtp_email", "smtp_pass"}

	if err := db.Model(&models.Config{}).Where("param IN ?", params).Find(&configs); err.Error != nil {
		log.Error(err.Error)
		return false
	}

	var host, port, email, password models.Config
	for _, config := range configs {
		switch config.Param {
		case "smtp_host":
			host = config
		case "smtp_port":
			port = config
		case "smtp_email":
			email = config
		case "smtp_pass":
			password = config
		}
	}

	if host.Value == "" || port.Value == "" || email.Value == "" || password.Value == "" {
		log.Error(host.Value, port.Value, email.Value, password.Value)
		log.Error("SMTP config not found or incorrect")
		return false
	}

	m := gomail.NewMessage()
	m.SetHeader("From", email.Value)

	m.SetHeader("To", recipient)

	m.SetHeader("Subject", subject)

	m.SetBody("text/plain", msg)

	prt, err := strconv.Atoi(port.Value)
	if err != nil {
		log.Errorf("Convert port error: %v", err)
		return false
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

func SendRegisterMail(email string, lang string, user models.User, code string, db *gorm.DB) bool {
	subject, msg := template.UserRegister(lang, user, code)

	val := Send(email, subject, msg, db)

	return val
}
