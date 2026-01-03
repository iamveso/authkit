package authkit

const (
	ErrorInvalidCredentials string = "invalid credentials"
)

type AuthKit struct{}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
	DummyHash()
}

func NewAuthKit() *AuthKit {
	return &AuthKit{}
}

func (a *AuthKit) HashPassword() (string, error) {}

func (a *AuthKit) PasswordAuthenticator() (bool, error) {}

func (a *AuthKit) GenerateOTP() string {}

func (a *AuthKit) PasswordlessGenrateEmailLink() (string, error) {}

func (a *AuthKit) PasswordlessVerifyEmailLink() error {}
