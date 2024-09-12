package requestData

type SmtpSettings struct {
	Host     string `json:"smtp_host"`
	Port     string `json:"smtp_port"`
	Email    string `json:"smtp_email"`
	Password string `json:"smtp_password"`
}
