package models

type Category struct {
	Name       string `json:"name"`
	CategoryID string `json:"category_id"`
	CreatorID  uint   `json:"creator_id"`
	Created    string `json:"created"`
	Updated    string `json:"updated"`
}

type CategoryDescription struct {
	CategoryID  string `json:"category_id"`
	Description string `json:"description"`
	Created     string `json:"created"`
	Updated     string `json:"updated"`
}

type CategoryImage struct {
	CategoryID string `json:"category_id"`
	Image      string `json:"image"`
	Created    string `json:"created"`
	Updated    string `json:"updated"`
}

type CategoryInfoByIdBody struct {
	CategoryID string `json:"category_id"`
}
