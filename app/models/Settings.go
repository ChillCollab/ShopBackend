package models

type Settings struct {
	SettingsSMTP
}

type SettingsSMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
