package tests

import (
	"backend_v1/internal/controllers/authController"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestActivate tests the Activate function
func TestActivate(t *testing.T) {
	// Set up a Gin router
	router := gin.Default()

	// Define a route for the Activate function
	router.GET("/activate/:code", authController.Activate)

	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/activate/test-code", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Create a mock Gin context
	context, _ := gin.CreateTestContext(rr)
	context.Request = req

	// Call the Activate function
	router.ServeHTTP(rr, req)

	// Check if the response status code is 200 OK
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check if the response body contains the expected message
	expectedResponse := `{"response":"Endpoint doesn't complete"}`
	assert.Equal(t, expectedResponse, rr.Body.String())
}
