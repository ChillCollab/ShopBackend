package body

type Login struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type Register struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Email   string `json:"email"`
}

type Send struct {
	Email string `json:"email"`
}

type Activate struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}
