package auth

import (
	dataBase "backend/internal/dataBase/models"
	"backend/internal/errorCodes"
	"backend/internal/middlewares/handlers"
	"backend/internal/middlewares/language"
	"backend/models"
	"backend/models/body"
	"backend/pkg/logger"
	"backend/pkg/utils"
	"errors"
	"net/http"
	"os"
	"time"
)

type ginResponse struct {
	Code   int
	Object any
}

func CheckTokens(user models.FullUserInfo, tokens models.AccessToken) (models.AccessToken, error) {
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		access, refresh, err := GenerateJWT(TokenData{
			Authorized: true,
			Email:      user.Email,
			Role:       user.Role,
		})

		if err != nil {
			return models.AccessToken{}, err
		}

		createdTokens := models.AccessToken{
			UserId:       user.ID,
			AccessToken:  access,
			RefreshToken: refresh,
		}

		createError := dataBase.DB.Model(models.AccessToken{}).Create(createdTokens).Error
		if createError != nil {
			return models.AccessToken{}, createError
		}

		return createdTokens, nil
	}

	alive, err := CheckTokenRemaining(tokens.AccessToken)
	if err != nil {
		return models.AccessToken{}, err
	}

	if alive <= 0 {
		access, refresh, err := GenerateJWT(TokenData{
			Authorized: true,
			Email:      user.Email,
			Role:       user.Role,
		})
		if err != nil {
			return models.AccessToken{}, err
		}

		createdTokens := models.AccessToken{
			UserId:       user.ID,
			AccessToken:  access,
			RefreshToken: refresh,
		}

		createError := dataBase.DB.Model(models.AccessToken{}).Where("user_id = ?", user.ID).Updates(createdTokens).Error
		if createError != nil {
			return models.AccessToken{}, createError
		}

		return createdTokens, nil
	}
	return tokens, nil
}

func RegisterHandler(user body.Register, lang string) (success bool, res ginResponse) {
	if user.Name == "" || user.Surname == "" {
		return false, ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "incorrect_name_or_surname"), errorCodes.NameOfSurnameIncorrect),
		}
	}
	if !utils.MailValidator(user.Email) {
		return false, ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "incorrect_email"), errorCodes.IncorrectEmail),
		}
	} else if user.Login == "" {
		return false, ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "login_empty"), errorCodes.LoginCanBeEmpty),
		}
	}

	if len(user.Name) > 32 || len(user.Surname) > 32 {
		return false, ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "name_surname_long"), errorCodes.IncorrectInfoData),
		}
	}

	if ok := utils.ValidateLogin(user.Login); !ok {
		return false, ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "login_can_be_include_letters_digits"), errorCodes.IncorrectLogin),
		}
	}

	var ifExist []models.User
	var foundLogin []models.User

	dataBase.DB.Where("email = ?", user.Email).Find(&ifExist)
	dataBase.DB.Model(&models.User{}).Where("login = ?", user.Login).Find(&foundLogin)

	if len(ifExist) > 0 {
		return false, ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "user_already_exist"), errorCodes.UserAlreadyExist),
		}
	}
	if len(foundLogin) > 0 {
		return false, ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "login_already_exist"), errorCodes.LoginAlreadyExist),
		}
	}

	return true, ginResponse{}
}

func CreateUser(user models.User, lang string) (res ginResponse, err error) {
	tx := dataBase.DB.Begin()

	create := tx.Create(&user)
	if create.Error != nil {
		tx.Rollback()
		return ginResponse{
			Code:   http.StatusInternalServerError,
			Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
		}, create.Error
	}

	roleError := tx.Create(&models.UserRole{ID: user.ID, Role: 0, Updated: dataBase.TimeNow()}).Error
	if roleError != nil {
		tx.Rollback()
		return ginResponse{
			Code:   http.StatusInternalServerError,
			Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
		}, roleError
	}

	tx.Commit()

	return ginResponse{}, nil
}

func SendHanlder(user models.User, lang string) (usr models.User, res ginResponse, err error) {

	if user.Email == "" {
		return models.User{},
			ginResponse{
				Code:   http.StatusBadRequest,
				Object: handlers.ResponseMsg(false, language.Language(lang, "user_not_registered"), errorCodes.UserNotFound),
			},
			errors.New("email is empty")
	}

	var foundUser models.User
	dataBase.DB.Model(&models.User{}).Where("email = ?", user.Email).First(&foundUser)
	if foundUser.Email == "" {
		return models.User{},
			ginResponse{
				Code:   http.StatusBadRequest,
				Object: handlers.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UserNotFound),
			},
			errors.New("user not found")
	}

	var checkUser []models.RegToken

	dataBase.DB.Model(&models.RegToken{}).Where("user_id = ?", foundUser.ID).Find(&checkUser)
	if len(checkUser) > 1 {
		del := dataBase.DB.Model(&checkUser).Delete(checkUser)
		if del.Error != nil {
			return models.User{},
				ginResponse{
					Code:   http.StatusInternalServerError,
					Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
				},
				del.Error
		}
		return models.User{},
			ginResponse{
				Code:   http.StatusForbidden,
				Object: handlers.ResponseMsg(false, language.Language(lang, "multiple_error"), errorCodes.MultipleData),
			},
			errors.New("multiple data")
	}
	if len(checkUser) > 0 {
		if checkUser[0].Created > time.Now().UTC().Add(-2*time.Minute).Format(os.Getenv("DATE_FORMAT")) {
			return models.User{},
				ginResponse{
					Code:   http.StatusBadRequest,
					Object: handlers.ResponseMsg(false, language.Language(lang, "email_already_sent")+user.Email, errorCodes.EmailAlreadySent),
				},
				errors.New("already sent")
		} else {
			del := dataBase.DB.Model(&models.RegToken{}).Delete("user_id = ?", checkUser[0].UserId)
			if del.Error != nil {
				return models.User{},
					ginResponse{
						Code:   http.StatusInternalServerError,
						Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
					},
					del.Error
			}
		}
	}

	return foundUser, ginResponse{}, nil
}

func SendRegEmail(user models.User, code string, mailType int) {

	logger := logger.GetLogger()

	create := dataBase.DB.Model(&models.RegToken{}).Create(models.RegToken{
		UserId:  int(user.ID),
		Type:    mailType,
		Code:    code,
		Created: dataBase.TimeNow(),
	})
	if create.Error != nil {
		logger.Error("Create mail in table error: " + create.Error.Error())
		return
	}

	if !utils.Send(
		user.Email,
		"Welcome to Admin Panel!", "Your link for countinue is: "+os.Getenv("DOMAIN")+"/registration/submit/"+code+
			"\n\nEmail: "+user.Email+
			"\nLogin: "+user.Name+
			"\nName: "+user.Name+
			"\nSurname: "+user.Surname+
			"\nCreated: "+user.Created,
		dataBase.DB) {
		logger.Error("Email send error to adderess: " + user.Email)
	}

	logger.Info("Email sent to adderess: " + user.Email)
}

func ActivateHandler(user body.Activate, lang string) (res ginResponse, err error) {
	if user.Code == "" {
		return ginResponse{
			Code:   http.StatusNotFound,
			Object: handlers.ResponseMsg(false, language.Language(lang, "incorrect_activation_code"), errorCodes.IncorrectActivationCode),
		}, errors.New("code is empty")
	}
	if user.Password == "" {
		return ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "password_null"), errorCodes.NameOfSurnameIncorrect),
		}, errors.New("password is empty")
	}
	digit, symb := utils.PasswordChecker(user.Password)
	if !digit || !symb {
		return ginResponse{
			Code:   http.StatusBadRequest,
			Object: handlers.ResponseMsg(false, language.Language(lang, "password_should_by_include_digits"), errorCodes.PasswordShouldByIncludeSymbols),
		}, errors.New("password should by include digits")
	}

	return ginResponse{}, nil
}

func ActivateByRegToken(user body.Activate, lang string) (usr models.User, res ginResponse, err error) {

	var activate models.RegToken

	tx := dataBase.DB.Begin()

	codesRes := dataBase.DB.Model(&models.RegToken{}).Where("code = ?", user.Code).First(&activate)
	if codesRes.RowsAffected <= 0 {
		return usr, ginResponse{
			Code:   http.StatusNotFound,
			Object: handlers.ResponseMsg(false, language.Language(lang, "activation_code_not_found"), errorCodes.ActivationCodeNotFound),
		}, errors.New("code not found")
	}
	if activate.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		deleteCode := tx.Model(&models.RegToken{}).Delete("code = ?", activate.Code)
		if deleteCode.Error != nil {
			tx.Rollback()
			return usr, ginResponse{
				Code:   http.StatusInternalServerError,
				Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
			}, deleteCode.Error
		}
		return usr, ginResponse{
			Code:   http.StatusUnauthorized,
			Object: handlers.ResponseMsg(false, language.Language(lang, "activation_code_expired"), errorCodes.ActivationCodeExpired),
		}, errors.New("code expired")
	}

	var foundUsers models.User
	dataBase.DB.Model(models.User{}).Where("id = ?", uint(activate.UserId)).First(&foundUsers)
	if foundUsers.ID <= 0 {
		return usr, ginResponse{
			Code:   http.StatusNotFound,
			Object: handlers.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UserNotFound),
		}, errors.New("user not found")
	}

	if foundUsers.Active {
		return usr, ginResponse{
			Code:   http.StatusForbidden,
			Object: handlers.ResponseMsg(false, language.Language(lang, "user_already_registered"), errorCodes.UserAlreadyRegistered),
		}, errors.New("user already registered")
	}

	var checkPass models.UserPass
	dataBase.DB.Model(&models.UserPass{}).Where("user_id = ?", activate.UserId).First(&checkPass)
	if checkPass.Pass != "" {
		deletePass := tx.Model(&models.UserPass{}).Delete("user_id = ?", activate.UserId)
		if deletePass.Error != nil {
			tx.Rollback()
			return usr, ginResponse{
				Code:   http.StatusInternalServerError,
				Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
			}, deletePass.Error
		}
	}
	deleteCode := tx.Model(&models.RegToken{}).Where("code = ?", activate.Code).Delete(activate)
	if deleteCode.Error != nil {
		tx.Rollback()
		return usr, ginResponse{
			Code:   http.StatusInternalServerError,
			Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
		}, deleteCode.Error
	}
	createPass := tx.Model(&models.UserPass{}).Create(models.UserPass{
		UserId:  uint(activate.UserId),
		Pass:    utils.Hash(user.Password),
		Updated: dataBase.TimeNow(),
	})
	if createPass.Error != nil {
		tx.Rollback()
		return usr, ginResponse{
			Code:   http.StatusInternalServerError,
			Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
		}, createPass.Error
	}
	update := tx.Model(&models.User{}).Where("id = ?", activate.UserId).Updates(models.User{
		Active:  true,
		Updated: dataBase.TimeNow(),
	})
	if update.Error != nil {
		tx.Rollback()
		return usr, ginResponse{
			Code:   http.StatusInternalServerError,
			Object: handlers.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
		}, update.Error
	}

	tx.Commit()

	return foundUsers, ginResponse{}, nil
}
