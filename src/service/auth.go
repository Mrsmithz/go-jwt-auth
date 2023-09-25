package service

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
)

var sampleSecretKey = []byte("JwtSampleSecretKey")

type AuthInterface interface {
	GenerateJwt(email string) (string, error)
	VerifyJwt(jwt string) (UserData, error)
}

type AuthService struct {
	AuthInterface
}

type UserData struct {
	Email string
	Exp   time.Time
}

type JwtClaims struct {
	Data UserData `json:"data"`
	jwt.MapClaims
}

func New() AuthInterface {
	service := &AuthService{}
	service.AuthInterface = service
	return service
}

func (s *AuthService) GenerateJwt(email string) (string, error) {
	claims := &JwtClaims{
		Data: UserData{
			Email: email,
			Exp:   time.Now().Add(180 * time.Minute),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString(sampleSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *AuthService) VerifyJwt(token string) (UserData, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(sampleSecretKey), nil
	}

	claims := &JwtClaims{}

	_, err := jwt.ParseWithClaims(token, claims, keyFunc)

	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(verr.Inner, errors.New("Token expired")) {
			return UserData{}, errors.New("Token expired")
		}
		return UserData{}, errors.New("Invalid token")
	}

	return claims.Data, nil
}
