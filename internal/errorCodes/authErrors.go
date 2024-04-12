package errorCodes

const (
	AuthErrors = iota + 0
	Unauthorized
	IncorrectEmail
	EmptyEmail

	UserNotFound
	UserIsNotActive
	ActivationCodeNotFound
	EmailSendError
	NameOfSurnameIncorrect
	EmptyFields
	UserAlreadyExist
	EmailAlreadySent
	IncorrectActivationCode
	PasswordShouldByIncludeSymbols
	ActivationCodeExpired
	NotFoundInUsers
	NotFoundRegistrationCode
	UserAlreadyRegistered
	CodeOrPasswordEmpty
	RecoveryCodeNotFound
	RecoveryCodeExpired
)
