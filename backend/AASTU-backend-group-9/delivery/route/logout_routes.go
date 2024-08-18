package route

import (
	"blog/config"
	"blog/database"
	"blog/delivery/controller"
	"blog/domain"
	"blog/repository"
	"blog/usecase"
	"time"

	"github.com/gin-gonic/gin"
)

func NewLogoutRouter(env *config.Env, timeout time.Duration, db database.Database, r *gin.RouterGroup) {
    tokenRepo := repository.NewMongoTokenRepository(db,domain.TokenCollection)
    logoutUsecase := usecase.NewLogoutUsecase(tokenRepo, timeout)
    logoutController := &controller.LogoutController{
        LogoutUsecase: logoutUsecase,
    }

    r.POST("/logout", logoutController.Logout)
}
