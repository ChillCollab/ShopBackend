package body

type CreateCategory struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Image       string `json:"image"`
}
