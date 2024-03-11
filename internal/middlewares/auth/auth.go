package auth

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenData struct {
	Authorized bool
	Email      string
}

func GenerateJWT(data TokenData) (string, string, error) {
	accessAlive, err := strconv.Atoi(os.Getenv("ACCESS_ALIVE"))
	if err != nil {
		return "", "", fmt.Errorf("error parsing ACCESS_ALIVE: %v", err)
	}

	refreshAlive, err := strconv.Atoi(os.Getenv("REFRESH_ALIVE"))
	if err != nil {
		return "", "", fmt.Errorf("error parsing REFRESH_ALIVE: %v", err)
	}

	access, err := generateToken(data, accessAlive, os.Getenv("JWT_SECRET"))
	if err != nil {
		return "", "", err
	}

	refresh, err := generateToken(data, refreshAlive, os.Getenv("JWT_SECRET")+"refr")
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func CheckTokenExpiration(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return true
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		exp := int64(claims["exp"].(float64))
		if exp < time.Now().Unix() {
			return true
		}
	}
	return false
}

func generateToken(data TokenData, alive int, signingKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = data.Authorized
	claims["email"] = data.Email
	claims["expired"] = time.Now().Add(time.Minute * time.Duration(alive)).Unix()

	tokenString, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", fmt.Errorf("error generating token: %v", err)
	}

	return tokenString, nil
}
