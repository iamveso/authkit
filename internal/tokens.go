package internal

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthKitJwtManager struct {
	Issuer string
	Secret string
}

type InternalClaims[T any] struct {
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Audience  string `json:"aud"`
	NotBefore int64  `json:"nbf"`
	Subject   string `json:"sub"`

	Data T `json:"data"`
}

// GetAudience implements jwt.Claims.
func (i InternalClaims[T]) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{i.Issuer}, nil
}

// GetExpirationTime implements jwt.Claims.
func (i InternalClaims[T]) GetExpirationTime() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(i.ExpiresAt, 0)}, nil
}

// GetIssuedAt implements jwt.Claims.
func (i InternalClaims[T]) GetIssuedAt() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(i.IssuedAt, 0)}, nil
}

// GetIssuer implements jwt.Claims.
func (i InternalClaims[T]) GetIssuer() (string, error) {
	return i.Issuer, nil
}

// GetNotBefore implements jwt.Claims.
func (i InternalClaims[T]) GetNotBefore() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(i.NotBefore, 0)}, nil
}

// GetSubject implements jwt.Claims.
func (i InternalClaims[T]) GetSubject() (string, error) {
	return i.Subject, nil
}

func (i InternalClaims[T]) Validate() error {
	return nil
}

func GenerateToken[T any](j *AuthKitJwtManager, ttl time.Duration, customData T) (string, error) {
	claims := InternalClaims[T]{
		Issuer:    j.Issuer,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Data:      customData,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.Secret))
}

func ParseToken[T any](j *AuthKitJwtManager, token string) (*T, error) {
	keyfunc := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.Secret), nil
	}

	var claims InternalClaims[T]
	parsedJwt, err := jwt.ParseWithClaims(token, &claims, keyfunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("token has expired")
		}
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	iss, err := parsedJwt.Claims.GetIssuer()
	if err != nil || iss != j.Issuer {
		return nil, fmt.Errorf("unrecognized issuer")
	}

	if !parsedJwt.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return &claims.Data, nil
}
