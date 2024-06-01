package images

import (
	"fmt"
	"os"
)

func AvatarUrl(imageId string) string {
	return fmt.Sprintf("http://"+os.Getenv("IP")+":"+os.Getenv("APP_PORT")+"/api_v1/user/avatar/%s", imageId)
}
