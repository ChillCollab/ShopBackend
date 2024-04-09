package authController

import (
	dataBase "backend_v1/internal/dataBase/models"
	errorcodes "backend_v1/internal/errorCodes"
	"backend_v1/internal/middlewares/auth"
	"backend_v1/internal/middlewares/handlers"
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

func Login(c *gin.Context) {
	var user models.UserLogin

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parse error!", errorcodes.ParsingError))
		return
	}

	if err := utils.JsonChecker(user, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.UnmarshalError))
		return
	}

	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Unmarshal error!", errorcodes.UnmarshalError))
		return
	}

	var foundUser []models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).Find(&foundUser)
	if len(foundUser) <= 0 {
		c.JSON(http.StatusUnauthorized, handlers.ErrMsg(false, "Incorrect email or password!", errorcodes.Unauthorized))
		return
	}
	if !foundUser[0].Active {
		c.JSON(401, handlers.ErrMsg(false, "User "+user.Email+" is not Active", errorcodes.UserIsNotActive))
		return
	}

	var passCheck models.UserPass
	dataBase.DB.Model(models.UserPass{}).Where("user_id = ?", foundUser[0].ID).First(&passCheck)
	userPass := utils.Hash(user.Password)
	if userPass != passCheck.Pass {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password", errorcodes.Unauthorized))
		return
	}

	var userRole models.UserRole
	dataBase.DB.Model(models.UserRole{}).Where("id = ?", foundUser[0].ID).First(&userRole)

	access, refresh, err := auth.GenerateJWT(auth.TokenData{
		Authorized: true,
		Email:      user.Email,
		Role:       userRole.Role,
	})
	if err != nil || refresh == "" || access == "" {
		panic(err)
	}

	var jwtCheck models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", strconv.Itoa(int(passCheck.UserId))).First(&jwtCheck)
	data := auth.JwtParse(jwtCheck.AccessToken)
	var foundUsr []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", data.Email).Find(&foundUsr)
	if jwtCheck.AccessToken != "" && jwtCheck.RefreshToken != "" {
		expRefresh := auth.CheckTokenExpiration(jwtCheck.RefreshToken)
		expAccess := auth.CheckTokenExpiration(jwtCheck.AccessToken)
		if expAccess || expRefresh {
			fmt.Println(0)
			dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", strconv.Itoa(int(passCheck.UserId))).Delete(jwtCheck)
		} else if len(foundUsr) <= 0 {
			dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", strconv.Itoa(int(passCheck.UserId))).Delete(jwtCheck)
		} else {

			rem, err := auth.CheckTokenRemaining(jwtCheck.AccessToken, c)
			if err != nil {
				panic(err)
			}
			c.JSON(http.StatusOK, models.UserLoginInfo{
				Info:         foundUser[0],
				AccessToken:  jwtCheck.AccessToken,
				RefreshToken: jwtCheck.RefreshToken,
				Alive:        rem,
			})
			fmt.Println(1)
			return
		}
	}

	dataBase.DB.Model(models.AccessToken{}).Create(models.AccessToken{
		UserId:       foundUser[0].ID,
		AccessToken:  access,
		RefreshToken: refresh,
	})
	rem, err := auth.CheckTokenRemaining(access, c)
	if err != nil {
		panic(err)
	}
	c.JSON(http.StatusOK, models.UserLoginInfo{
		Info:         foundUser[0],
		AccessToken:  access,
		RefreshToken: refresh,
		Alive:        rem,
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
	if valid := utils.MailValidator(user.Email); !valid {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Incorrect email", errorcodes.IncorrectEmail))
		return
	}

	var ifExist []models.User

	dataBase.DB.Where("email = ?", user.Email).Find(&ifExist)
	if len(ifExist) > 0 {
		c.JSON(403, handlers.ErrMsg(false, "User with the same email already exist", errorcodes.UserAlreadyExist))
		return
	}

	completeUser := models.User{
		Login:   user.Login,
		Name:    user.Name,
		Surname: user.Surname,
		Email:   user.Email,
		Created: time.Now().UTC().Format(os.Getenv("DATE_FORMAT")),
		Updated: time.Now().UTC().Format(os.Getenv("DATE_FORMAT")),
	}

	create := dataBase.DB.Model(&models.User{}).Create(&completeUser)

	if create.Error != nil {
		fmt.Println("DB Error:", create.Error)
		c.JSON(403, handlers.ErrMsg(false, "DB error, please check logs", errorcodes.DBError))
		return
	}

	var createdUser []models.User
	dataBase.DB.Model(models.User{}).Where("email = ?", completeUser.Email).Find(&createdUser)
	if len(createdUser) <= 0 {
		c.JSON(http.StatusInternalServerError, handlers.ErrMsg(false, "Created user was not found in table 'users'", errorcodes.NotFoundInUsers))
		return
	}

	dataBase.DB.Model(models.UserRole{}).Create(&models.UserRole{ID: createdUser[0].ID, Role: 0})

	c.JSON(http.StatusOK, gin.H{
		"error": false,
		"user":  completeUser,
	})
}

func Send(c *gin.Context) {
	var user models.SendMail

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parse error!", errorcodes.ParsingError))
		return
	}
	if err := utils.JsonChecker(user, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(400, gin.H{
			"error": "Parse error",
		})
		return
	}
	if user.Email == "" {
		c.JSON(401, handlers.ErrMsg(false, "User was not registered", errorcodes.UserNotFound))
		return
	}

	var foundUser models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(403, handlers.ErrMsg(false, "User was not found", errorcodes.UserNotFound))
		return
	}

	var checkUser models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).First(&checkUser)
	if checkUser.Created < time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", checkUser.UserId).Delete(models.RegToken{UserId: checkUser.UserId, Type: 0})
	} else {
		c.JSON(403, handlers.ErrMsg(false, "Email already sent to address: "+user.Email, errorcodes.EmailAlreadySent))
		return
	}

	code := utils.CodeGen()

	dataBase.DB.Model(&models.RegToken{}).Create(models.RegToken{
		UserId:  int(foundUser.ID),
		Type:    0,
		Code:    code,
		Created: time.Now().UTC().Format(os.Getenv("DATE_FORMAT")),
	})

	if utils.Send(
		foundUser.Email,
		"Welcome to Admin Panel!", "Your link for countinue is: https://"+os.Getenv("DOMAIN")+"/acc/activate/"+code+
			"\n\nEmail: "+user.Email+
			"\nLogin: "+foundUser.Name+
			"\nName: "+foundUser.Name+
			"\nSurname: "+foundUser.Surname+
			"\nCreated: "+foundUser.Created,
	) {
		c.JSON(200, handlers.ErrMsg(true, "Email sent to "+foundUser.Email, 0))
		return
	} else {
		c.JSON(403, handlers.ErrMsg(false, "Email did't send. Pls, check logs", errorcodes.EmailSendError))
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
		c.JSON(404, handlers.ErrMsg(false, "Incorrect activation code!", errorcodes.IncorrectActivationCode))
		return
	}
	if user.Password == "" {
		c.JSON(403, handlers.ErrMsg(false, "Password can't be null", errorcodes.NameOfSurnameIncorrect))
		return
	}
	digit, symb := utils.PasswordChecker(user.Password)
	if !digit || !symb {
		c.JSON(403, handlers.ErrMsg(false, "Password should be include Digits and Symbols", errorcodes.PasswordShouldByIncludeSymbols))
		return
	}

	var activate models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("code = ?", user.Code).First(&activate)
	if activate.Code == "" {
		c.JSON(403, handlers.ErrMsg(false, "Activation code was not found", errorcodes.ActivationCodeNotFound))
		return
	}
	if activate.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("code = ?", activate.Code).Delete(activate)
		c.JSON(401, handlers.ErrMsg(false, "Your activaton code was expired! Request a new activation code.", errorcodes.ActivationCodeExpired))
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

	c.JSON(200, handlers.ErrMsg(true, "Account "+user.Email+" was successful activate!", 0))
}

func Refresh(c *gin.Context) {
	token := auth.CheckAuth(c, false)
	if token == "" {
		fmt.Println(5)
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password", errorcodes.Unauthorized))
		return
	}
	fmt.Println(token)
	data := auth.JwtParse(token)
	if data.Email == nil {
		fmt.Println(6)
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password!", errorcodes.Unauthorized))
		return
	}
	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parse error!", errorcodes.ParsingError))
		return
	}
	var dataToken auth.Token
	if err := utils.JsonChecker(dataToken, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &dataToken); err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Unmarshal error!", errorcodes.UnmarshalError))
		return
	}

	var user models.User
	fmt.Println(data)
	dataBase.DB.Model(models.User{}).Where("email = ?", data.Email).First(&user)
	if user.ID == 0 {
		fmt.Println(3)
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password!", errorcodes.Unauthorized))
		return
	}

	var foundToken models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", token).First(&foundToken)
	if foundToken.AccessToken == "" || foundToken.RefreshToken == "" {
		fmt.Println(2)
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password!", errorcodes.Unauthorized))
		return
	}

	if uint(foundToken.UserId) != user.ID {
		panic("Check user access tokens. Found id != userID from jwt")
	}

	if auth.CheckTokenExpiration(dataToken.Token) {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password!", errorcodes.Unauthorized))
		return
	}

	if dataToken.Token != foundToken.RefreshToken {
		fmt.Println(1)
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password!", errorcodes.Unauthorized))
		return
	}

	dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", strconv.Itoa(int(user.ID))).Delete(foundToken)
	access, refresh, err := auth.GenerateJWT(auth.TokenData{
		Authorized: true,
		Email:      user.Email,
	})
	if err != nil || refresh == "" || access == "" {
		panic(err)
	}

	newTokens := models.AccessToken{
		UserId:       user.ID,
		AccessToken:  access,
		RefreshToken: refresh,
	}

	dataBase.DB.Model(models.AccessToken{}).Create(newTokens)
	c.JSON(http.StatusOK, newTokens)
}

func Logout(c *gin.Context) {
	token := auth.GetAuth(c)
	if token == "" {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password!", errorcodes.Unauthorized))
		return
	}
	var foundToken []models.AccessToken
	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", token).Find(&foundToken)
	if len(foundToken) == 0 {
		c.JSON(401, handlers.ErrMsg(false, "Incorrect email or password!", errorcodes.Unauthorized))
		return
	}
	if len(foundToken) > 1 {
		if err := fmt.Errorf("a lot of access tokens for same user"); err != nil {
			panic(err)
		}
	}

	dataBase.DB.Model(models.AccessToken{}).Where("access_token = ?", foundToken[0].AccessToken).Delete(&foundToken)
	c.JSON(200, handlers.ErrMsg(true, "Token deleted", 0))
}

func Recovery(c *gin.Context) {
	var user models.SendMail

	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, "Parse error!", errorcodes.ParsingError))
		return
	}
	if err := utils.JsonChecker(user, rawData, c); err != "" {
		c.JSON(http.StatusBadRequest, handlers.ErrMsg(false, err, errorcodes.ParsingError))
		return
	}
	if err := json.Unmarshal(rawData, &user); err != nil {
		c.JSON(400, gin.H{
			"error": "Parse error",
		})
		return
	}
	if user.Email == "" {
		c.JSON(401, handlers.ErrMsg(false, "Field 'Email' can't be empty!", errorcodes.EmptyEmail))
		return
	}

	var foundUser models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		c.JSON(200, handlers.ErrMsg(true, "Email sent to "+user.Email, 0))
		return
	}

	var checkUser models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).First(&checkUser)
	if checkUser.Created < time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
		dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", checkUser.UserId).Delete(models.RegToken{UserId: checkUser.UserId, Type: 0})
	} else {
		c.JSON(403, handlers.ErrMsg(false, "Email already sent to address: "+user.Email, errorcodes.EmailAlreadySent))
		return
	}

	code := utils.CodeGen()

	dataBase.DB.Model(&models.RegToken{}).Create(models.RegToken{
		UserId:  int(foundUser.ID),
		Type:    1,
		Code:    code,
		Created: time.Now().UTC().Format(os.Getenv("DATE_FORMAT")),
	})

	if utils.Send(
		foundUser.Email,
		"Admin Panel password recovery!", "Your link for countinue is: https://"+os.Getenv("DOMAIN")+"/acc/activate/"+code+
			"\n\nEmail: "+user.Email+
			"\nLogin: "+foundUser.Name+
			"\nName: "+foundUser.Name+
			"\nSurname: "+foundUser.Surname+
			"\nCreated: "+foundUser.Created,
	) {
		c.JSON(200, handlers.ErrMsg(true, "Email sent to "+foundUser.Email, 0))
		return
	} else {
		c.JSON(403, handlers.ErrMsg(false, "Email did't send. Pls, check logs", errorcodes.EmailSendError))
		return
	}
}
