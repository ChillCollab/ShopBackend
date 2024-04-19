package utils

import (
	"crypto/tls"
	"fmt"
	"os"
	"regexp"
	"strconv"

	gomail "gopkg.in/mail.v2"
)

func MailValidator(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	match, _ := regexp.MatchString(emailRegex, email)
	return match
}

func Send(recipient string, subject string, msg string) bool {
	if !MailValidator(recipient) {
		fmt.Println("Validate mail error: Email " + recipient + " is not valid")
		return false
	}

	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("SMTP_EMAIL"))

	m.SetHeader("To", recipient)

	m.SetHeader("Subject", subject)

	m.SetBody("text/plain", msg)

	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		fmt.Println(err)
		return false
	}

	d := gomail.NewDialer(os.Getenv("SMTP_HOST"), port, os.Getenv("SMTP_EMAIL"), os.Getenv("SMTP_PASSWORD"))

	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		fmt.Println(err)
		panic(err)
	}
	fmt.Println("Email was sent to: " + recipient)
	return true
}
