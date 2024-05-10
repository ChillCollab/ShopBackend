package models

type FullUserInfo struct {
	ID      uint   `gorm:"unique" json:"id"`
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Role    int    `json:"role"`
	Active  bool   `json:"active"`
	Pass    string `json:"pass"`
	Alive   int    `json:"alive"`
	Created string `json:"created"`
	Updated string `json:"updated"`
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

type SendMail struct {
	Email string `json:"email"`
}

type Activate struct {
	Code     string `json:"code"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegistrationCodeBody struct {
	Code string `json:"code"`
}

type CodeCheckResponse struct {
	ID      uint   `gorm:"unique" json:"id"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
}

type UserLogin struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type RegToken struct {
	UserId  int    `gorm:"unique" json:"user_id"`
	Type    int    `json:"type"`
	Code    string `json:"code"`
	Created string `json:"created"`
}

type AuthToken struct {
	UserId       uint   `gorm:"unique" json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RejectedToken struct {
	UserId       uint   `gorm:"unique" json:"user_id"`
	AccessToken  string `gorm:"unique" json:"access_token"`
	RefreshToken string `gorm:"unique" json:"refresh_token"`
}

type ChangePassword struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type RecoverySubmit struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}
