package utils

type MailerCfg struct {
	Host     string
	Port     string
	Password string
}

type Email struct {
	From    string
	To      string
	Subject string
	Message string
}
