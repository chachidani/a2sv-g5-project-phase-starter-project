package domain

import (
	"github.com/gin-gonic/gin"
)

type Blog_Controller_interface interface {
	CreateBlog() gin.HandlerFunc
	GetOneBlog() gin.HandlerFunc
	GetBlogs() gin.HandlerFunc
	UpdateBlog() gin.HandlerFunc
	DeleteBlog() gin.HandlerFunc
	FilterBlog() gin.HandlerFunc
}

type Blog_Usecase_interface interface {
	CreateBlog(iblog PostBlog) (Blog, error)
	GetOneBlog(id string) (Blog, error)
	GetBlogs(limit int, page_number int) ([]Blog, error)
	UpdateBlog(id string, blog Blog) (Blog, error)
	DeleteBlog(id string, user_id string) error
	FilterBlog(map[string]string) ([]Blog, error)
}

type Blog_Repository_interface interface {
	CreateBlogDocunent(blog Blog) (Blog, error)
	GetOneBlogDocunent(id string) (Blog, error)
	GetBlogDocunents(offset int, limit int) ([]Blog, error)
	UpdateBlogDocunent(id string, blog Blog) (Blog, error)
	DeleteBlogDocument(id string, userID string) error
	FilterBlogDocunent(map[string]string) ([]Blog, error)
}
