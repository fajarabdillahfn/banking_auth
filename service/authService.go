package service

import (
	"errors"
	"fmt"
	"log"

	"github.com/fajarabdillahfn/banking_auth/domain"
	"github.com/fajarabdillahfn/banking_auth/dto"
	"github.com/golang-jwt/jwt"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, error)
	Verify(urlParams map[string]string) error
	Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, error)
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo: repo, rolePermissions: permissions}
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, error) {
	var login *domain.Login

	login, err := s.repo.FindBy(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	claims := login.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)
	if err != nil {
		return nil, err
	}

	var accessToken string
	if accessToken, err = authToken.NewAccessToken(); err != nil {
		return nil, err
	}

	return &dto.LoginResponse{AccessToken: accessToken}, nil
}

func (s DefaultAuthService) Verify(urlParams map[string]string) error {
	// convert the string token to JWT struct
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return err
	} else {
		/*
			Checking the validity of the token, this verifies the expiry
			time and the signature of the token
		*/
		if jwtToken.Valid {
			// type cast the token claims to jwt.MapClaims
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			//converting the token claims to Claims struct
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return errors.New("request not verified")
				}
			}
			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return fmt.Errorf("%s role is not authorized", claims.Role)
			}

			return nil

		} else {
			return errors.New("invalid token")
		}
	}
}

func (s DefaultAuthService) Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, error) {
	if vErr := request.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			var err error
			// continue with the refresh token functionality
			if err := s.repo.RefreshTokenExists(request.RefreshToken); err != nil {
				return nil, err
			}
			//generate an access token from refresh token
			var accessToken string
			if accessToken, err = domain.NewAccessTokenFromRefreshToken(request.RefreshToken); err != nil {
				return nil, err
			}
			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errors.New("invalid token")
	}
	return nil, errors.New("cannot generate a new access token until the current one expires")
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		log.Println("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}
