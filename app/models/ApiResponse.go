package models

func ResponseMsg(success bool, message string, code int) interface{} {
	if code == 0 {
		return SuccessResponse{
			Success: success,
			Message: message,
		}
	}

	return ErrorResponse{
		Success: success,
		Message: message,
		Code:    code,
	}
}
