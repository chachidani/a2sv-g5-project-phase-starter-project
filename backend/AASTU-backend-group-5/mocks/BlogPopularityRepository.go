// Code generated by mockery v2.44.1. DO NOT EDIT.

package mocks

import (
	domain "github.com/RealEskalate/blogpost/domain"
	mock "github.com/stretchr/testify/mock"
)

// BlogPopularityRepository is an autogenerated mock type for the BlogPopularityRepository type
type BlogPopularityRepository struct {
	mock.Mock
}

// GetPopularBlogs provides a mock function with given fields: sortBy, sortOrder
func (_m *BlogPopularityRepository) GetPopularBlogs(sortBy string, sortOrder int) ([]domain.Blog, error) {
	ret := _m.Called(sortBy, sortOrder)

	if len(ret) == 0 {
		panic("no return value specified for GetPopularBlogs")
	}

	var r0 []domain.Blog
	var r1 error
	if rf, ok := ret.Get(0).(func(string, int) ([]domain.Blog, error)); ok {
		return rf(sortBy, sortOrder)
	}
	if rf, ok := ret.Get(0).(func(string, int) []domain.Blog); ok {
		r0 = rf(sortBy, sortOrder)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]domain.Blog)
		}
	}

	if rf, ok := ret.Get(1).(func(string, int) error); ok {
		r1 = rf(sortBy, sortOrder)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewBlogPopularityRepository creates a new instance of BlogPopularityRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewBlogPopularityRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *BlogPopularityRepository {
	mock := &BlogPopularityRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
