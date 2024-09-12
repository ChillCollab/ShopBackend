package errorCodes

const (
	AdminErrors = iota + 300
	UndefinedUserRole
	IncorrectUserPhone
	IncorrectUserLogin
	CategoryAlreadyExists
	CategoryNotFound
	CategoriesListEmpty
	AvatarSizelimit
	DeleteAvatarError
	ActionLogsEmpty
	CategoryUpdateError
	IncorrectDataCreateUser
	CreateUserError
	ErrorGetConfig
)
