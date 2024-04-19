package utils

import (
	"backend/models"
	"fmt"
	"net/mail"
	"net/smtp"
	"regexp"
	"strings"

	"gorm.io/gorm"
)

func MailValidator(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	match, _ := regexp.MatchString(emailRegex, email)
	return match
}

func Send(recipient string, subject string, msg string, db *gorm.DB) bool {
	if !MailValidator(recipient) {
		fmt.Println("Validate mail error: Email " + recipient + " is not valid")
		return false
	}

	var host models.Config
	var port models.Config
	var username models.Config
	var password models.Config
	db.Model(&models.Config{}).Where("param = ?", "mail_host").First(&host)
	db.Model(&models.Config{}).Where("param = ?", "mail_port").First(&port)
	db.Model(&models.Config{}).Where("param = ?", "mail_username").First(&username)
	db.Model(&models.Config{}).Where("param = ?", "mail_password").First(&password)
	if host.Value == "" || port.Value == "" {
		fmt.Println("==============================")
		fmt.Println(host.Value, port.Value, username.Value, password.Value)
		fmt.Println("==============================")
		panic("mail config not found or incorrect")
	}

	addr := host.Value + ":" + port.Value

	fromName := "Fred"
	fromEmail := "fred@example.com"
	toNames := []string{"Ted"}
	toEmails := []string{"ted@example.com"}
	body := "This is the body of your email"
	// Build RFC-2822 email
	toAddresses := []string{}

	for i, _ := range toEmails {
		to := mail.Address{toNames[i], toEmails[i]}
		toAddresses = append(toAddresses, to.String())
	}

	toHeader := strings.Join(toAddresses, ", ")
	from := mail.Address{fromName, fromEmail}
	fromHeader := from.String()
	subjectHeader := subject
	header := make(map[string]string)
	header["To"] = toHeader
	header["From"] = fromHeader
	header["Subject"] = subjectHeader
	header["Content-Type"] = `text/html; charset="UTF-8"`

	for k, v := range header {
		msg += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	msg += "\r\n" + body
	bMsg := []byte(msg)
	// Send using local postfix service
	c, err := smtp.Dial(addr)

	if err != nil {
		return false
	}

	defer c.Close()
	if err = c.Mail(fromHeader); err != nil {
		return false
	}

	for _, addr := range toEmails {
		if err = c.Rcpt(addr); err != nil {
			return false
		}
	}

	w, err := c.Data()
	if err != nil {
		return false
	}
	_, err = w.Write(bMsg)
	if err != nil {
		return false
	}

	err = w.Close()
	if err != nil {
		return false
	}

	err = c.Quit()
	// Or alternatively, send with remote service like Amazon SES
	// err = smtp.SendMail(addr, auth, fromEmail, toEmails, bMsg)
	// Handle response from local postfix or remote service
	if err != nil {
		return false
	}

	return true
	// m := gomail.NewMessage()
	// m.SetHeader("From", os.Getenv("SMTP_EMAIL"))

	// m.SetHeader("To", recipient)

	// m.SetHeader("Subject", subject)

	// m.SetBody("text/plain", msg)

	// port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	// if err != nil {
	// 	fmt.Println(err)
	// 	return false
	// }

	// d := gomail.NewDialer(os.Getenv("SMTP_HOST"), port, os.Getenv("SMTP_EMAIL"), os.Getenv("SMTP_PASSWORD"))

	// d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// if err := d.DialAndSend(m); err != nil {
	// 	fmt.Println(err)
	// 	panic(err)
	// }
	// fmt.Println("Email was sent to: " + recipient)
	// return true
}
