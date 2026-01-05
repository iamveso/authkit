package authkit

import (
	"fmt"
	"time"

	"github.com/gorilla/sessions"
	"github.com/iamveso/authkit/internal"
)

const (
	ErrorInvalidCredentials string = "invalid credentials"
)

type AuthenticationStrategy string

func (as AuthenticationStrategy) isValid() bool {
	switch as {
	case Sessions, Tokens:
		return true
	}
	return false
}

const (
	Sessions AuthenticationStrategy = "session"
	Tokens   AuthenticationStrategy = "token"
)

type AuthKit struct {
	Hasher  PasswordHasher
	Storage Store
}

type Option func(*AuthKit)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
	DummyHash()
}

func WithHasher(hasher PasswordHasher) Option {
	return func(ak *AuthKit) {
		ak.Hasher = hasher
	}
}

type AuthKitUser interface {
	GetPassword() string
}

type Store interface {
	FindUserByIdentifier(identifier string) (AuthKitUser, error)
}

type AuthenticationDetails struct {
	Session sessions.Session
	Token   string
}

type AuthKitSession struct {
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	IsRevoked bool      `json:"is_revoked"`
}

func NewAuthKit(store Store, opts ...Option) *AuthKit {
	// defaults
	authkit := &AuthKit{
		Storage: store,
		Hasher:  &internal.DefaultPasswordHasher{},
	}
	for _, opt := range opts {
		opt(authkit)
	}
	return authkit
}

func (ak *AuthKit) HashPassword(password string) (string, error) {
	return ak.Hasher.Hash(password)
}

// Identifier is either username, phone number or some other form of identification that is unique in the db
func (ak *AuthKit) PasswordAuthenticator(identifier string, password string, strategy AuthenticationStrategy) (AuthenticationDetails, error) {
	var authenticationDetails = AuthenticationDetails{}
	user, err := ak.Storage.FindUserByIdentifier(identifier)
	if err != nil || !strategy.isValid() {
		ak.Hasher.DummyHash() //to prevent timing attacks
		return authenticationDetails, err
	}

	if !ak.Hasher.Verify(password, user.GetPassword()) {
		return authenticationDetails, fmt.Errorf(ErrorInvalidCredentials)
	}

	switch strategy {
	case Sessions:
	case Tokens:
	}
	return authenticationDetails, nil
}

// func (ak *AuthKit) GenerateOTP() string {}

// func (ak *AuthKit) PasswordlessGenrateEmailLink() (string, error) {}

// func (ak *AuthKit) PasswordlessVerifyEmailLink() error {}

// func (ak *AuthKit) ValidateSession(session *sessions.Session) (AuthKitSession, error) {}

// func (ak *AuthKit) VerifyToken(token string) (map[string]any, error) {}
