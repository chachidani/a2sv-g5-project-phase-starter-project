package router

import (
	"os"

	"aait.backend.g10/delivery/controllers"
	"aait.backend.g10/infrastructures"
	"aait.backend.g10/repositories"
	"aait.backend.g10/usecases"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

func NewRouter(db *mongo.Database) {
	router := gin.Default()

	jwtService := infrastructures.Jwt{JwtSecret: os.Getenv("JWT_SECRET")}

	userRepo := repositories.NewUserRepository(db, os.Getenv("USER_COLLECTION"))

	pwdService := infrastructures.PwdService{}
	emailService := infrastructures.EmailService{}

	blogRepo := repositories.NewBlogRepository(db, os.Getenv("BLOG_COLLECTION"))
	blogUseCase := usecases.NewBlogUseCase(blogRepo, userRepo)
	blogController := controllers.NewBlogController(blogUseCase)

	commentRepo := repositories.NewCommentRepository(db, os.Getenv("COMMENT_COLLECTION_NAME"))
	commentController := controllers.CommentController{
		CommentUsecase: usecases.NewCommentUsecase(commentRepo),
	}

	likeRepo := repositories.NewLikeRepository(db, os.Getenv("LIKE_COLLECTION_NAME"))
	likeController := controllers.LikeController{
		LikeUseCase: usecases.NewLikeUseCase(likeRepo),
	}

	authUsecases := usecases.NewAuthUsecase(userRepo, jwtService, pwdService, emailService)
	authController := controllers.NewAuthController(authUsecases, controllers.GoogleOAuthConfig)

	userUseCase := usecases.NewUserUseCase(userRepo)
	userController := controllers.NewUserController(userUseCase)

	router.POST("/blogs", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, blogController.CreateBlog)
	router.GET("/blogs", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, blogController.GetAllBlogs)
	router.GET("/blogs/:id", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, blogController.GetBlogByID)
	router.PUT("/blogs/:id", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, blogController.UpdateBlog)
	router.DELETE("/blogs/:id", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, blogController.DeleteBlog)
	router.PATCH("/blogs/:id/view", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, blogController.AddView)
	router.GET("/blogs/search", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, blogController.SearchBlogs)

	router.PATCH("/users/promote", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, infrastructures.AdminMiddleWare(), userController.PromoteUser)

	router.GET("/comment/:blog_id", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, commentController.GetComments)
	router.GET("/comment_count/:blog_id", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, commentController.GetCommentsCount)
	router.POST("/comment", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, commentController.AddComment)
	router.PUT("/comment/:id", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, commentController.UpdateComment)
	router.DELETE("/comment/:id", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, commentController.DelelteComment)

	router.PUT("/like", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, likeController.LikeBlog)
	router.DELETE("/like", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, likeController.DeleteLike)
	router.GET("/like/:blog_id", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, likeController.BlogLikeCount)

	router.POST("/register", authController.Register)
	router.POST("/login", authController.Login)
	router.POST("/refresh", authController.RefreshToken)
	router.POST("/refresh-token", authController.RefreshToken)
	router.POST("/forgot-password", authController.ForgotPassword)
	router.POST("/reset-password", authController.ResetPassword)
	router.GET("/auth/google", authController.HandleGoogleLogin)
	router.GET("/auth/google/callback", authController.HandleGoogleCallback)
	router.POST("/upload-image", infrastructures.AuthMiddleware(&jwtService), authController.VerifyUserAccessToken, userController.UploadProfilePic)

	port := os.Getenv("PORT")
	router.Run(":" + port)
}
