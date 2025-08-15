package responses

type ChangeEmail struct {
	Success      bool   `json:"success"`
	Messages     string `json:"messages"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
