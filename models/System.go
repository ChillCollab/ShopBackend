package models

type SysConfig struct {
	Param   string `gorm:"unique" json:"param"`
	Value   string `json:"value"`
	Updated string `json:"updated"`
}
