package requestData

type Login struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type Register struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
}

type Send struct {
	Email string `json:"email"`
}

type Activate struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

type Refresh struct {
	Token string `json:"token"`
}

type ChangeEmail struct {
	Email string `json:"email"`
}

type CheckRecoveryCode struct {
	Code string `json:"code"`
}

type RegistrationCode struct {
	Code string `json:"code"`
}

type SendMail struct {
	Email string `json:"email"`
}

type RecoverySubmit struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

type ChangeUser struct {
	ID      uint   `gorm:"unique" json:"id"`
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Role    int    `json:"role"`
	Active  bool   `json:"active"`
}

type CategoryUpdate struct {
	CategoryID  string `json:"category_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Image       string `json:"image"`
}
