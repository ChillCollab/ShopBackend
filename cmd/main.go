package main

import (
	config "backend/internal"
	"log"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

func main() {

	if err := config.Run(); err != nil {
		log.Fatalf("error run config: %v", err)
	}
}
