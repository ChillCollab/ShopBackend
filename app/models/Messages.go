package models

type Messages struct {
	UserId  int    `json:"user_id"`
	Type    int    `json:"type"`
	Created string `json:"created"`
}
