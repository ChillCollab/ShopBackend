package responses

type CreateUserAdmin struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	User    UserInfo
}
