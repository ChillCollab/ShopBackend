package responses

type UserInfo struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Role    int    `json:"role"`
	Created string `json:"created"`
	Updated string `json:"updated"`
}

type AuthResponse struct {
	User         UserInfo `json:"user"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	Alive        int      `json:"alive"`
}

type RegisterResponse struct {
	Error bool     `json:"error"`
	User  UserInfo `json:"user"`
}
