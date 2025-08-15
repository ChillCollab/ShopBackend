package broker

import (
	"encoding/json"
	"os"

	"github.com/go-redis/redis"
)

type Client struct {
	Client *redis.Client
}

// var ctx = context.Background()

func RedisInit() (red *Client, errors error) {

	client := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_HOST"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}

	return &Client{Client: client}, nil
}

func (c *Client) RedisAddToArray(tableName string, models interface{}) error {
	dataJSON, err := c.Client.Get(tableName).Bytes()
	if err != nil && err != redis.Nil {
		return err
	}

	var datas []interface{}
	if len(dataJSON) > 0 {
		if err := json.Unmarshal(dataJSON, &datas); err != nil {
			return err
		}
	}

	datas = append(datas, models)

	updatedTokensJSON, err := json.Marshal(datas)
	if err != nil {
		return err
	}

	return c.Client.Set("auth_tokens", updatedTokensJSON, 0).Err()
}

func (c *Client) RedisGetArray(tableName string) ([]interface{}, error) {
	dataJSON, err := c.Client.Get(tableName).Bytes()
	if err != nil && err != redis.Nil {
		return nil, err
	}

	var datas []interface{}
	if len(dataJSON) > 0 {
		if err := json.Unmarshal(dataJSON, &datas); err != nil {
			return nil, err
		}
	}

	return datas, nil
}
