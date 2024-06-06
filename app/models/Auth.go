package models

type FullUserInfo struct {
	ID       uint   `gorm:"unique" json:"id"`
	Login    string `json:"login"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	RoleId   int    `json:"role_id"`
	AvatarId string `json:"avatar_id"`
	Active   bool   `json:"active"`
	Pass     string `json:"pass"`
	Alive    int    `json:"alive"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
}

type UserLoginInfo struct {
	Info         User   `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Alive        int    `json:"alive"`
}

type TokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Activate struct {
	Code     string `json:"code"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserLogin struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type RegToken struct {
	UserId  int    `json:"user_id"`
	Type    int    `json:"type"`
	Code    string `json:"code"`
	Created string `json:"created"`
}

type RejectedToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
