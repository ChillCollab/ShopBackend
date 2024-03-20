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

type ChangePassword struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type ChangeUser struct {
	ID      uint   `gorm:"unique" json:"id"`
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
	Active  bool   `json:"active"`
}

type UserInfo struct {
	Info         User   `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Alive        int    `json:"alive"`
}

type UsersArray struct {
	ID []int `json:"id"`
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

type AccessToken struct {
	UserId       uint   `json:"user_id`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
