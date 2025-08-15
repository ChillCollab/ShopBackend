package template

import (
	"backend/models"
	"backend/models/language"
	"os"
)

func UserRegister(lang string, user models.User, code string) (subj string, msg string) {
	return language.Language(lang, "welcome_admin_panel"),
		language.Language(lang, "link_to_register") + os.Getenv("DOMAIN") + "/registration/submit/" + code +
			"\n\nEmail: " + user.Email +
			"\nLogin: " + user.Name +
			"\nName: " + user.Name +
			"\nSurname: " + user.Surname +
			"\nCreated: " + user.Created
}
