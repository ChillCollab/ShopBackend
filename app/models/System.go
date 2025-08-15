package models

type SysConfig struct {
	Param   string `gorm:"unique" json:"param"`
	Value   string `json:"value"`
	Updated string `json:"updated"`
}

type Config struct {
	Param    string `gorm:"unique" json:"param"`
	Value    string `json:"value"`
	Activate bool   `json:"activate"`
	Updated  string `json:"updated"`
}

type ActionLogs struct {
	Id      int    `gorm:"unique" json:"id"`
	Login   string `json:"login"`
	Action  string `json:"action"`
	Ip      string `json:"ip"`
	Created string `json:"created"`
}
