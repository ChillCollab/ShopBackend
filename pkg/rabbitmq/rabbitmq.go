package rabbitmq

import (
	"fmt"

	"github.com/streadway/amqp"
)

type RabbitMQ struct {
	IP       string
	Port     string
	Username string
	Password string
}

func New(ip string, port string, username string, password string) *RabbitMQ {
	return &RabbitMQ{
		IP:       ip,
		Port:     port,
		Username: username,
		Password: password,
	}
}

func (rabbit *RabbitMQ) Init() error {
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s:%s/", rabbit.Username, rabbit.Password, rabbit.IP, rabbit.Port))
	if err != nil {
		return err
	}
	defer conn.Close()

	return nil
}
