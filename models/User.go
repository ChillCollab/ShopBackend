package models

type User struct {
	ID       uint   `gorm:"unique" json:"id"`
	Login    string `gorm:"unique" json:"login"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Email    string `gorm:"unique" json:"email"`
	Phone    string `json:"phone"`
	AvatarId string `json:"avatar_id"`
	Active   bool   `json:"active"`
	RoleId   int    `json:"role_id"`
	Pass     string `json:"pass"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
}

type UserRole struct {
	ID      uint   `gorm:"unique" json:"id"`
	Role    int    `json:"role"`
	Updated string `json:"updated"`
}

type UserInfo struct {
	User
	Role int `json:"role"`
}

type EmailChangeRequest struct {
	Email string `json:"email"`
}
type EmailChange struct {
	UserID  uint   `json:"user_id"`
	Email   string `json:"email"`
	Code    int    `json:"code"`
	Created string `json:"created"`
}

type EmailChangeComplete struct {
	Code int `json:"code"`
}

type EmailChangeResponse struct {
	Success      bool   `json:"success"`
	Messages     string `json:"messages"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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
