package middlewares

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type TokenData struct {
	Authorized bool
	Email      string
	Role       int
}
type JwtData struct {
	Authorized interface{} `json:"authorized"`
	Email      interface{} `json:"email"`
	Role       interface{} `json:"role"`
	Expired    interface{} `json:"expired"`
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

	refresh, err := generateToken(data, refreshAlive, os.Getenv("JWT_SECRET"))
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
		exp := int64(claims["expired"].(float64))
		if exp < time.Now().Unix() {
			return true
		}
	}
	return false
}

func JwtParse(jw string) JwtData {
	token, err := jwt.Parse(jw, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return JwtData{}
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		auth := claims["authorized"]
		email := claims["email"]
		exp := claims["expired"]
		role := claims["role"]
		return JwtData{
			Authorized: auth,
			Email:      email,
			Role:       role,
			Expired:    exp,
		}
	}
	return JwtData{}
}

func generateToken(data TokenData, alive int, signingKey string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = data.Authorized
	claims["email"] = data.Email
	claims["role"] = data.Role
	claims["expired"] = time.Now().Add(time.Minute * time.Duration(alive)).Unix()

	tokenString, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", fmt.Errorf("error generating token: %v", err)
	}

	return tokenString, nil
}

func CheckTokenRemaining(token string) (int, error) {
	data := JwtParse(token)
	if data.Email == nil {
		return 0, fmt.Errorf("incorrect email")
	}
	remaningTime := time.Unix(int64(data.Expired.(float64)), 0).Sub(time.Now().UTC())

	return int(remaningTime.Seconds()), nil
}

func GetAuth(c *gin.Context) string {
	token := c.GetHeader("Authorization")
	cleanedToken := strings.Replace(token, "Bearer ", "", 1)

	return cleanedToken
}

func GetToken(c *gin.Context) string {
	token := strings.Replace(c.GetHeader("Authorization"), "Bearer ", "", 1)
	if token == "" {
		return ""
	}
	return token
}
