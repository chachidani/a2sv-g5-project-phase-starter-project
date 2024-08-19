package infrastructure

import (
	"context"

	config "github.com/aait.backend.g5.main/backend/Config"
	interfaces "github.com/aait.backend.g5.main/backend/Domain/Interfaces"
	models "github.com/aait.backend.g5.main/backend/Domain/Models"
	"github.com/google/uuid"
)

type urlService struct {
	env  *config.Env
	repo interfaces.URLServiceRepository
	ctx  context.Context
}

func NewURLService(env *config.Env, repo interfaces.URLServiceRepository) interfaces.URLService {
	return &urlService{
		env:  env,
		repo: repo,
		ctx:  context.Background(),
	}
}

func (uc *urlService) GenerateURL(token string) (string, *models.ErrorResponse) {
	short_url_code := uuid.New().String()
	baseUrl := uc.env.BASE_URL

	url := models.URL{
		ShortURLCode: short_url_code,
		Token:        token,
	}

	if err := uc.repo.SaveURL(url, uc.ctx); err != nil {
		return "", models.InternalServerError("Error while saving the URL")
	}

	return baseUrl + "/" + short_url_code, nil

}

func (uc *urlService) RemoveURL(short_url_code string) *models.ErrorResponse {
<<<<<<< HEAD
	_, err := uc.repo.DeleteURL(short_url_code, uc.ctx)
=======
	err := uc.repo.DeleteURL(short_url_code, uc.ctx)
>>>>>>> origin/aait.backend.g5.bisrat.setup-db-and-user-repo

	if err != nil {
		return models.InternalServerError("Error while deleting the URL")
	}

	return nil
}

func (uc *urlService) GetURL(short_url_code string) (*models.URL, *models.ErrorResponse) {
	url, err := uc.repo.GetURL(short_url_code, uc.ctx)

	if err != nil {
		return nil, models.InternalServerError("Error while getting the URL")
	}

	return url, nil
}
