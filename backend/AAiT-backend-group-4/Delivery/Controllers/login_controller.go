package controllers

import (
	bootstrap "aait-backend-group4/Bootstrap"
	domain "aait-backend-group4/Domain"
	"net/http"

	"github.com/gin-gonic/gin"
)

type LoginController struct {
	LoginUsecase domain.LoginUsecase
	Env          *bootstrap.Env
}

// Login is a method of the LoginController struct that handles the login functionality.
// It receives a gin.Context object as a parameter and binds the JSON request to the domain.LoginRequest struct.
// If the JSON binding fails, it returns a JSON response with a bad request error.
// Otherwise, it calls the LoginWithIdentifier method of the LoginUsecase to perform the login operation.
// If the login operation fails, it returns a JSON response with an error message.
// Finally, it returns a JSON response with the access token and refresh token.
func (lc *LoginController) Login(c *gin.Context) {
	var request domain.LoginRequest

	err := c.ShouldBindJSON(&request)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	accessToken, refreshToken, err := lc.LoginUsecase.LoginWithIdentifier(c, request.Identifier)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	msg := map[string]string{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	}

	c.JSON(http.StatusOK, msg)
}
