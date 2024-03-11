package models

type User struct {
	ID      uint   `gorm:"unique" json:"id"`
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
	Active  bool   `json:"active"`
	Created string `json:"created"`
	Updated string `json:"updated"`
}

type SendMail struct {
	Email string `json:"email"`
}

type Activate struct {
	Code     string `json:"code"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserPass struct {
	UserId  uint   `gorm:"unique" json:"user_id"`
	Pass    string `json:"pass"`
	Updated string `json:"update"`
}

type UserLogin struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegToken struct {
	UserId  int    `json:"user_id"`
	Type    int    `json:"type"`
	Code    string `json:"code"`
	Created string `json:"created"`
}
