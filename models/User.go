package models

type User struct {
	ID      uint   `gorm:"unique" json:"id"`
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Active  bool   `json:"active"`
	Created string `json:"created"`
	Updated string `json:"updated"`
}

type UserRole struct {
	ID   uint `gorm:"unique" json:"id`
	Role int  `json:"role"`
}

type UserInfo struct {
	User
	Role int `json:"role"`
}

type ChangeUser struct {
	ID      uint   `gorm:"unique" json:"id"`
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Role    int    `json:"role"`
}

type ChangeUserInfo struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Phone   string `json:"phone"`
}

type UsersArray struct {
	ID []int `json:"id"`
}
type UserPass struct {
	UserId  uint   `gorm:"unique" json:"user_id"`
	Pass    string `json:"pass"`
	Updated string `json:"updated"`
}
