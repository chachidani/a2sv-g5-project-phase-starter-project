package infrastructure

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AdminMiddleware checks if the user is an admin
func AdminMiddleware(jwtService JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		token, claims, err := jwtService.ValidateToken(tokenString)

		if err != nil || !token.Valid {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		isAdmin := claims.Role

		if isAdmin == "is_admin" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}
}

// AuthMiddleware checks if the user is authenticated
func AuthMiddleware(jwtService JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		token, claims, err := jwtService.ValidateToken(tokenString)
		if err != nil || !token.Valid {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// You can use the claims, e.g., setting them in the context for later use
		c.Set("userID", claims.ID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

		c.Next()
	}
}
