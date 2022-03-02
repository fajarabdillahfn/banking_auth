package dto

import (
	"errors"

	"github.com/fajarabdillahfn/banking_auth/domain"
	"github.com/golang-jwt/jwt"
)

type RefreshTokenRequest struct {
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (r RefreshTokenRequest) IsAccessTokenValid() *jwt.ValidationError {
	_, err := jwt.Parse(r.AccessToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		var vErr *jwt.ValidationError
		if errors.As(err, &vErr) {
			return vErr
		}
	}
	return nil
}