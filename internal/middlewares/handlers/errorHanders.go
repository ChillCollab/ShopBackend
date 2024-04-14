package handlers

import (
	"backend_v1/models"
)

func ErrMsg(success bool, message string, code int) interface{} {
	if code == 0 {
		return models.SuccessResponse{
			Success: success,
			Message: message,
		}
	} else {
		return models.ErrorResponse{
			Success: success,
			Message: message,
			Code:    code,
		}
	}
}
