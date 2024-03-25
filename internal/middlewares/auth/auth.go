package auth

import (
	dataBase "backend_v1/internal/dataBase/models"
	"backend_v1/models"
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
type jwtData struct {
	Authorized interface{} `json:"authorized"`
	Email      interface{} `json:"email"`
	Role       interface{} `json:"role"`
	Expired    interface{} `json:"expired"`
}

type Token struct {
	Token string `json:"token"`
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

func JwtParse(jw string) jwtData {
	token, err := jwt.Parse(jw, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return jwtData{}
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		auth := claims["authorized"]
		email := claims["email"]
		exp := claims["expired"]
		return jwtData{
			Authorized: auth,
			Email:      email,
			Expired:    exp,
		}
	}
	return jwtData{}
}

func CheckAdmin(jw string) bool {
	data := JwtParse(jw)
	return data.Role != 0
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

func CheckTokenRemaining(token string, c *gin.Context) (int, error) {
	data := JwtParse(token)
	if data.Email == nil {
		c.JSON(401, gin.H{
			"error": "Incorrect email or password!",
		})
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

func CheckAuth(c *gin.Context, checkExpiried bool) string {
	token := strings.Replace(c.GetHeader("Authorization"), "Bearer ", "", 1)
	if token == "" {
		fmt.Println(11)
		return ""
	}

	var dbToken []models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", token).Find(&dbToken)
	if len(dbToken) <= 0 {
		fmt.Println(12)
		return ""
	}
	if checkExpiried {
		if expired := CheckTokenExpiration(token); expired {
			fmt.Println(13)
			return ""
		}
	}
	userEmail := JwtParse(token).Email
	if userEmail == "" {
		panic("incorrect user email")
	}
	var foundUsers []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", userEmail).Find(&foundUsers)
	if len(foundUsers) <= 0 {
		fmt.Println(14)
		return ""
	}

	return token
}
