package authController

import (
	dataBase "backend_v1/internal/dataBase/models"
	"backend_v1/internal/middlewares/auth"
	"backend_v1/models"
	utils "backend_v1/pkg/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

func errMsg(err bool, message string) gin.H {
	return gin.H{
		"success": err,
		"message": message,
	}
}

func Login(c *gin.Context) {
	var user models.UserLogin
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "Parse error",
		})
		return
	}

	var foundUser models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(401, errMsg(false, "User "+user.Email+" is not exist!"))
		return
	}

	var passCheck models.UserPass
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", foundUser.ID).First(&passCheck)
	userPass := utils.Hash(user.Password)
	if userPass != passCheck.Pass {
		c.JSON(401, errMsg(false, "Incorrect password"))
		return
	}
	access, refresh, err := auth.GenerateJWT(auth.TokenData{
		Authorized: true,
		Email:      user.Email,
	})
	if err != nil || refresh == "" || access == "" {
		panic(err)
	}

	alive, err := strconv.Atoi(os.Getenv("ACCESS_ALIVE"))
	if err != nil {
		panic(err)
	}

	c.JSON(http.StatusOK, models.UserInfo{
		Info:         foundUser,
		AccessToken:  access,
		RefreshToken: refresh,
		Alive:        alive,
	})
}

func Register(c *gin.Context) {

	var user models.User

	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "Parse error",
		})
		return
	}

	if user.Name == "" || user.Surname == "" {
		c.JSON(400, gin.H{
			"error": "Name or Surname is not correct",
		})
		return
	} else if user.Email == "" {
		c.JSON(400, gin.H{
			"error": "Your email is not correct. Please write the correct email",
		})
		return
	} else if user.Login == "" {
		c.JSON(400, gin.H{
			"error": "You need to send Login",
		})
		return
	}

	var ifExist models.User

	dataBase.DB.Where("email = ?", user.Email).First(&ifExist)
	if ifExist.Email != "" {
		c.JSON(403, errMsg(false, "User with the same email already exist"))
		return
	}

	create := dataBase.DB.Model(&models.User{}).Create(&models.User{
		Login:   user.Login,
		Name:    user.Name,
		Surname: user.Surname,
		Email:   user.Email,
		Created: time.Now().UTC().Format(os.Getenv("DATE_FORMAT")),
		Updated: time.Now().UTC().Format(os.Getenv("DATE_FORMAT")),
	})

	if create.Error != nil {
		fmt.Println("DB Error:", create.Error)
		c.JSON(403, errMsg(false, "DB error, please check logs"))
		return
	}

	c.JSON(200, gin.H{
		"response": "Endpoint doesn't complete",
	})
}

func Send(c *gin.Context) {
	var user models.SendMail

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, errMsg(false, "Parse error!"))
		return
	}
	if err := utils.JsonChecker(user, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, errMsg(false, err))
		return
	}
	fmt.Println(c.Request.Body)
	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(400, gin.H{
			"error": "Parse error",
		})
		return
	}
	if user.Email == "" {
		c.JSON(401, errMsg(false, "User was not registered"))
		return
	}

	var foundUser models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(403, errMsg(false, "User was not found"))
		return
	}

	var checkUser models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).First(&checkUser)
	if checkUser.Created < time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", checkUser.UserId).Delete(models.RegToken{UserId: checkUser.UserId, Type: 0})
	} else {
		c.JSON(403, errMsg(false, "Email already sent to address: "+user.Email))
		return
	}

	code := utils.CodeGen()

	dataBase.DB.Model(&models.RegToken{}).Create(models.RegToken{
		UserId:  int(foundUser.ID),
		Type:    0,
		Code:    code,
		Created: time.Now().UTC().Format(os.Getenv("DATE_FORMAT")),
	})

	if utils.Send(foundUser.Email, "Welcome to Admin Panel!", "Your link for countinue is: https://"+os.Getenv("DOMAIN")+"/acc/activate/"+code) {
		c.JSON(200, errMsg(true, "Email sent to "+foundUser.Email))
		return
	} else {
		c.JSON(403, errMsg(false, "Email did't send. Pls, check logs"))
		return
	}
}

func Activate(c *gin.Context) {
	var user models.Activate
	err := c.ShouldBindJSON(&user)
	if err != nil {
		panic(err)
	}
	if user.Code == "" {
		c.JSON(404, errMsg(false, "Incorrect activation code!"))
		return
	}
	if user.Password == "" {
		c.JSON(403, errMsg(false, "Password can't be null"))
		return
	}
	digit, symb := utils.PasswordChecker(user.Password)
	if !digit || !symb {
		c.JSON(403, errMsg(false, "Password should be include Digits and Symbols"))
		return
	}

	var activate models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("code = ?", user.Code).First(&activate)
	if activate.Code == "" {
		c.JSON(403, errMsg(false, "Activation code was not found"))
		return
	}
	if activate.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("code = ?", activate.Code).Delete(activate)
		c.JSON(401, errMsg(false, "Your activaton code was expired! Request a new activation code."))
		return
	}
	var checkPass models.UserPass
	dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", activate.UserId).First(&checkPass)
	if checkPass.Pass != "" {
		dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", activate.UserId).Delete(checkPass)
	}
	dataBase.DB.Model(&models.RegToken{}).Where("code = ?", activate.Code).Delete(activate)
	dataBase.DB.Model(&models.UserPass{}).Create(models.UserPass{
		UserId:  uint(activate.UserId),
		Pass:    utils.Hash(user.Password),
		Updated: time.Now().UTC().Format(os.Getenv("DATE_FORMAT")),
	})
	dataBase.DB.Model(&models.User{}).Where("id = ?", activate.UserId).Update("active", true)

	c.JSON(200, errMsg(true, "Account"+user.Email+"was successful activate!"))
}

func Logout(c *gin.Context) {
	c.JSON(200, gin.H{
		"response": "Endpoint doesn't complate",
	})
}

func Recovery(c *gin.Context) {
	c.JSON(200, gin.H{
		"response": "Endpoint doesn't complate",
	})
}
