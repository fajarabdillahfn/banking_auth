package service

import (
	"github.com/fajarabdillahfn/banking_auth/domain"
	"github.com/fajarabdillahfn/banking_auth/dto"
)

type AuthService interface {
	Login(dto.LoginRequest) (*string, error)
}

func NewAuthService(repo domain.AuthRepository) DefaultAuthService {
	return DefaultAuthService{repo: repo}
}

type DefaultAuthService struct {
	repo domain.AuthRepository
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*string, error) {
	login, err := s.repo.FindBy(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	token, err := login.GenerateToken()
	if err != nil {
		return nil, err
	}
	return token, nil
}
