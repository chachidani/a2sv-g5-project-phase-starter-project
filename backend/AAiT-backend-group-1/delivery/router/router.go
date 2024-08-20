package router

import (
	"github.com/RealEskalate/a2sv-g5-project-phase-starter-project/aait-backend-group-1/domain"
	"github.com/RealEskalate/a2sv-g5-project-phase-starter-project/aait-backend-group-1/infrastructure"
	"github.com/gin-gonic/gin"

)

func SetupRouter(userController domain.UserController, blogController domain.BlogController, blogAssistantController domain.BlogAssistantController, jwtService domain.JwtService) *gin.Engine {
	r := gin.Default()

	// Public routes
	r.POST("/register", userController.Register)
	r.POST("/login", userController.Login)
	r.POST("/forgot-password", userController.ForgotPassword)
	r.POST("/logout", userController.Logout)
	r.PUT("/update-profile", userController.UpdateProfile)

	// Protected routes
	authMiddleware := infrastructure.NewMiddlewareService(jwtService)
	r.Use(authMiddleware.Authenticate())

	// user related routes
	r.POST("/promote", authMiddleware.Authorize("admin"), userController.PromoteUser)
	r.POST("/demote", authMiddleware.Authorize("admin"), userController.DemoteUser)

	// Blog routes
	blogRoutes := r.Group("/blogs")
	{
		blogRoutes.POST("/", blogController.CreateBlog)
		blogRoutes.GET("/:id", blogController.GetBlog)
		blogRoutes.GET("/", blogController.GetBlogs)
		blogRoutes.PUT("/:id", blogController.UpdateBlog)
		blogRoutes.DELETE("/:id", blogController.DeleteBlog)
		blogRoutes.GET("/search/title", blogController.SearchBlogsByTitle)
		blogRoutes.GET("/search/author", blogController.SearchBlogsByAuthor)
		blogRoutes.GET("/filter", blogController.FilterBlogs)
		blogRoutes.POST("/:id/like", blogController.LikeBlog)
		blogRoutes.POST("/:id/dislike", blogController.DislikeBlog)
		blogRoutes.POST("/:id/comments", blogController.AddComment)
		blogRoutes.DELETE("/:id/comments/:comment_id", blogController.DeleteComment)
		blogRoutes.PUT("/:id/comments/:comment_id", blogController.EditComment)
	}

	// blog assistant related routes
	r.POST("/generate-blog", blogAssistantController.GenerateBlog)
	r.POST("/enhance-blog", blogAssistantController.EnhanceBlog)
	r.GET("/suggest-blog", blogAssistantController.SuggestBlog)

	return r
}
