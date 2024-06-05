package requestData

type UsersArray struct {
	ID []int `json:"id"`
}

type ChangePassword struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type ChangeUserInfo struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Phone   string `json:"phone"`
}

type ChangeEmailComplete struct {
	Code int `json:"code"`
}
