package responses

type CategoryInfo struct {
	CategoryID  string `json:"category_id"`
	Name        string `json:"name"`
	Image       string `json:"image"`
	Description string `json:"description"`
	CreatorID   uint   `json:"creator_id"`
	Created     string `json:"created"`
	Updated     string `json:"updated"`
}
