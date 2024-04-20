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

type CategoryCreateBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Image       string `json:"image"`
}

type CategoryqInfo struct {
	CategoryID string `json:"category_id"`
	Name       string `json:"name"`
	Image      string `json:"image"`
	CreatorID  uint   `json:"creator_id"`
	Created    string `json:"created"`
	Updated    string `json:"updated"`
}

type CategoryUpdateBody struct {
	CategoryID  string `json:"category_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Image       string `json:"image"`
}

type CategoryDeleteBody struct {
	CategoryID []string `json:"category_id"`
}
