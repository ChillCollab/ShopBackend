package requestData

type SmtpSettings struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
