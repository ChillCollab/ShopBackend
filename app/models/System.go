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
