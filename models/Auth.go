package models

type UserLoginInfo struct {
	Info         User   `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Alive        int    `json:"alive"`
}

type SendMail struct {
	Email string `json:"email"`
}

type Activate struct {
	Code     string `json:"code"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegistarionCodeBody struct {
	Code string `json:"code"`
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
	UserId       uint   `gorm:"unique" json:"user_id`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type ChangePassword struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type RecoverySubmit struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}
