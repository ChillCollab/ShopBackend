package requestData

type CategoryDelete struct {
	CategoryID []string `json:"category_id"`
}

type CreateUser struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Email    string `json:"email"`
	SendMail bool   `json:"send_mail"`
}
