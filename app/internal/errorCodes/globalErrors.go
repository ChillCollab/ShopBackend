package errorCodes

const (
	GlobalErrors = iota + 500
	DBError
	ParsingError
	UnmarshalError
	MultipleData
	ServerError
)
