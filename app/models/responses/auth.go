package responses

type UserInfo struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Email    string `json:"email"`
	AvatarId string `json:"avatar_id"`
	Phone    string `json:"phone"`
	Role     int    `json:"role"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
}

type AuthResponse struct {
	User         UserInfo `json:"user"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	Alive        int      `json:"alive"`
}

type RegisterResponse struct {
	Error bool     `json:"error"`
	User  UserInfo `json:"user"`
}

type Refresh struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserId       int    `json:"user_id"`
}

type CheckRecoveryCode struct {
	ID      uint   `gorm:"unique" json:"id"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
}

type CodeCheck struct {
	ID      uint   `gorm:"unique" json:"id"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
}
