package route

import (
	"blog/config"
	"blog/database"
	"blog/delivery/middleware"
	"time"

	"github.com/gin-gonic/gin"
)

func Setup(env *config.Env, timeout time.Duration, db database.Database, gin *gin.Engine) {
	publicRouter := gin.Group("")
	// All Public APIs
	NewSignupRouter(env, timeout, db, publicRouter)
	NewLoginRouter(env, timeout, db, publicRouter)
	RegisterBlogRoutes(env, timeout, db, publicRouter)
	NewForgotPasswordRouter(env, db, publicRouter)
	// NewRefreshTokenRouter(env, timeout, db, publicRouter)

	protectedRouter := gin.Group("")
	// Middleware to verify AccessToken
	protectedRouter.Use(middleware.AuthMidd)
	// All Private APIs
  	NewProfileRouter(env, timeout, db, protectedRouter)
	NewLogoutRouter(env, timeout, db, protectedRouter)

  

}
