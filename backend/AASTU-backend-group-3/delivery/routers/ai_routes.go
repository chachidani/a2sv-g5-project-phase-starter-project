package routers

import "github.com/gin-gonic/gin"

func SetUpAi(router *gin.Engine) {
	ai := router.Group("/ai")
	{
		ai.GET("/content-suggestions", authMiddleware, aiController.ContentSuggestions)
		ai.POST("/ai/content-enhancements", authMiddleware, aiController.ContentEnhancements)
	}
}