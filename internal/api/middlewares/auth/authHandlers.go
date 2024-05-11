package auth

import (
	"errors"
	"net/http"
	"os"
	"time"

	"gorm.io/gorm"

	"backend/internal/dataBase"
	"backend/internal/errorCodes"
	"backend/models"
	"backend/models/body"
	"backend/models/language"
	"backend/pkg/logger"
	"backend/pkg/utils"
)

type ginResponse struct {
	Code   int
	Object any
}

// SendRegEmail это все не middleware
func SendRegEmail(user models.User, code string, mailType int, db *gorm.DB) {

	logger := logger.GetLogger()

	create := db.Model(&models.RegToken{}).Create(models.RegToken{
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
		"Welcome to Admin Panel!", "Your link for continue is: "+os.Getenv("DOMAIN")+"/registration/submit/"+code+
			"\n\nEmail: "+user.Email+
			"\nLogin: "+user.Name+
			"\nName: "+user.Name+
			"\nSurname: "+user.Surname+
			"\nCreated: "+user.Created,
		db) {
		logger.Error("Email send error to address: " + user.Email)
	}

	logger.Info("Email sent to address: " + user.Email)
}

func ActivateHandler(user body.Activate, lang string) (res ginResponse, err error) {
	if user.Code == "" {
		return ginResponse{
			Code:   http.StatusNotFound,
			Object: models.ResponseMsg(false, language.Language(lang, "incorrect_activation_code"), errorCodes.IncorrectActivationCode),
		}, errors.New("code is empty")
	}
	if user.Password == "" {
		return ginResponse{
			Code:   http.StatusBadRequest,
			Object: models.ResponseMsg(false, language.Language(lang, "password_null"), errorCodes.NameOfSurnameIncorrect),
		}, errors.New("password is empty")
	}
	digit, symb := utils.PasswordChecker(user.Password)
	if !digit || !symb {
		return ginResponse{
			Code:   http.StatusBadRequest,
			Object: models.ResponseMsg(false, language.Language(lang, "password_should_by_include_digits"), errorCodes.PasswordShouldByIncludeSymbols),
		}, errors.New("password should by include digits")
	}

	return ginResponse{}, nil
}

func ActivateByRegToken(user body.Activate, lang string, db *gorm.DB) (usr models.User, res ginResponse, err error) {

	var activate models.RegToken

	tx := db.Begin()

	// создал транзакцию и забил хуй
	codesRes := db.Model(&models.RegToken{}).Where("code = ?", user.Code).First(&activate)
	if codesRes.RowsAffected <= 0 {
		return usr, ginResponse{
			Code:   http.StatusNotFound,
			Object: models.ResponseMsg(false, language.Language(lang, "activation_code_not_found"), errorCodes.ActivationCodeNotFound),
		}, errors.New("code not found")
	}
	if activate.Created < time.Now().UTC().Add(-24*time.Hour).Format(os.Getenv("DATE_FORMAT")) {
		deleteCode := tx.Model(&models.RegToken{}).Delete("code = ?", activate.Code)
		if deleteCode.Error != nil {
			tx.Rollback()
			return usr, ginResponse{
				Code:   http.StatusInternalServerError,
				Object: models.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
			}, deleteCode.Error
		}
		return usr, ginResponse{
			Code:   http.StatusUnauthorized,
			Object: models.ResponseMsg(false, language.Language(lang, "activation_code_expired"), errorCodes.ActivationCodeExpired),
		}, errors.New("code expired")
	}

	var foundUsers models.User
	db.Model(models.User{}).Where("id = ?", uint(activate.UserId)).First(&foundUsers)
	if foundUsers.ID <= 0 {
		return usr, ginResponse{
			Code:   http.StatusNotFound,
			Object: models.ResponseMsg(false, language.Language(lang, "user_not_found"), errorCodes.UserNotFound),
		}, errors.New("user not found")
	}

	if foundUsers.Active {
		return usr, ginResponse{
			Code:   http.StatusForbidden,
			Object: models.ResponseMsg(false, language.Language(lang, "user_already_registered"), errorCodes.UserAlreadyRegistered),
		}, errors.New("user already registered")
	}

	var checkPass models.UserPass
	db.Model(&models.UserPass{}).Where("user_id = ?", activate.UserId).First(&checkPass)
	if checkPass.Pass != "" {
		deletePass := tx.Model(&models.UserPass{}).Delete("user_id = ?", activate.UserId)
		if deletePass.Error != nil {
			tx.Rollback()
			return usr, ginResponse{
				Code:   http.StatusInternalServerError,
				Object: models.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
			}, deletePass.Error
		}
	}
	deleteCode := tx.Model(&models.RegToken{}).Where("code = ?", activate.Code).Delete(activate)
	if deleteCode.Error != nil {
		tx.Rollback()
		return usr, ginResponse{
			Code:   http.StatusInternalServerError,
			Object: models.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
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
			Object: models.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
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
			Object: models.ResponseMsg(false, language.Language(lang, "db_error"), errorCodes.DBError),
		}, update.Error
	}

	tx.Commit()

	return foundUsers, ginResponse{}, nil
}
