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

type AuthKit[U AuthKitUser] struct {
	Hasher     PasswordHasher
	Storage    Store[U]
	JwtManager internal.AuthKitJwtManager
}

type Option[U AuthKitUser] func(*AuthKit[U])

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
	DummyHash()
}

func WithHasher[U AuthKitUser](hasher PasswordHasher) Option[U] {
	return func(ak *AuthKit[U]) {
		ak.Hasher = hasher
	}
}

func WithJwtConfig[U AuthKitUser](jwtManager internal.AuthKitJwtManager) Option[U] {
	return func(ak *AuthKit[U]) {
		ak.JwtManager = jwtManager
	}
}

type AuthKitUser interface {
	GetPassword() string
}

type Store[U AuthKitUser] interface {
	FindUserByIdentifier(identifier string) (U, error)
}

type tokenConfig struct {
	secret string
	issuer string
}

type sessionConfig struct{}
type AuthenticationDetails[U AuthKitUser] struct {
	Session       sessions.Session
	Token         string
	tokenConfig   tokenConfig
	sessionConfig sessionConfig
	User          U
}

func (a *AuthenticationDetails[U]) GenerateSession() {}

func (a *AuthenticationDetails[U]) GenerateToken(ttl time.Duration, customClaims any) (string, error) {
	return internal.GenerateToken(&internal.AuthKitJwtManager{Issuer: a.tokenConfig.issuer, Secret: a.tokenConfig.secret}, ttl, customClaims)
}

type AuthKitSession struct {
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	IsRevoked bool      `json:"is_revoked"`
}

func NewAuthKit[U AuthKitUser](store Store[U], secret string, opts ...Option[U]) *AuthKit[U] {
	// defaults
	authkit := &AuthKit[U]{
		Storage: store,
		Hasher:  &internal.DefaultPasswordHasher{},
		JwtManager: internal.AuthKitJwtManager{
			Issuer: "iamveso-lib",
			Secret: secret,
		},
	}
	for _, opt := range opts {
		opt(authkit)
	}
	return authkit
}

func (ak *AuthKit[U]) HashPassword(password string) (string, error) {
	return ak.Hasher.Hash(password)
}

// Identifier is either username, phone number or some other form of identification that is unique in the db
func (ak *AuthKit[U]) PasswordAuthenticator(identifier string, password string) (AuthenticationDetails[U], error) {
	var authenticationDetails = AuthenticationDetails[U]{}
	user, err := ak.Storage.FindUserByIdentifier(identifier)
	if err != nil {
		ak.Hasher.DummyHash() //to prevent timing attacks
		return authenticationDetails, fmt.Errorf(ErrorInvalidCredentials)
	}

	if !ak.Hasher.Verify(password, user.GetPassword()) {
		return authenticationDetails, fmt.Errorf(ErrorInvalidCredentials)
	}
	authenticationDetails.User = user
	authenticationDetails.tokenConfig = tokenConfig{issuer: ak.JwtManager.Issuer, secret: ak.JwtManager.Secret}
	return authenticationDetails, nil
}

// func (ak *AuthKit[U]) GenerateOTP() string {}

// func (ak *AuthKit[U]) PasswordlessGenrateEmailLink() (string, error) {}

// func (ak *AuthKit[U]) PasswordlessVerifyEmailLink() error {}

// func (ak *AuthKit[U]) ValidateSession(session *sessions.Session) (AuthKitSession, error) {}

// func (ak *AuthKit[U]) VerifyToken(token string) (map[string]any, error) {}
