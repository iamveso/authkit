package internal

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserClaims struct {
	ID   int    `json:"id"`
	Role string `json:"role"`
}

var testMgr = &AuthKitJwtManager{
	Issuer: "test-lib-issuer",
	Secret: "test-lib-secret",
}

func TestJwtFlow(t *testing.T) {
	data := UserClaims{ID: 1, Role: "user"}
	ttl := 1 * time.Hour

	t.Run("Success: Generate and Parse", func(t *testing.T) {
		token, err := GenerateToken(testMgr, ttl, data)
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		parsedData, err := ParseToken[UserClaims](testMgr, token)
		if err != nil {
			t.Fatalf("failed to verify and parse token data: %v", err)
		}

		if parsedData.ID != data.ID || parsedData.Role != data.Role {
			t.Errorf("Data mismatch, got %+v, want %+v", parsedData, data)
		}
	})

	t.Run("Security: Expired Token", func(t *testing.T) {
		token, _ := GenerateToken(testMgr, -1*time.Second, data)
		_, err := ParseToken[UserClaims](testMgr, token)

		if err == nil {
			t.Errorf("Expected error for expired token but got nil")
		}

		if err.Error() != "token has expired" {
			t.Errorf("Expected 'token has expired' error, got %v", err)
		}
	})

	t.Run("Security: Wrong Secret", func(t *testing.T) {
		token, _ := GenerateToken(testMgr, ttl, data)

		wrongMgr := &AuthKitJwtManager{Issuer: "test-lib-issuer", Secret: "WRONG-SECRET"}

		_, err := ParseToken[UserClaims](wrongMgr, token)
		if err == nil {
			t.Error("Expected error due to signature mismatch, but got nil")
		}
	})

	t.Run("Security: Wrong Issuer", func(t *testing.T) {
		token, _ := GenerateToken(testMgr, ttl, data)
		wrongMgr := &AuthKitJwtManager{Issuer: "test-issuer", Secret: "test-lib-secret"}
		_, err := ParseToken[UserClaims](wrongMgr, token)

		if err == nil {
			t.Errorf("Expected error due to different issuer being used")
		}

		if err.Error() != "unrecognized issuer" {
			t.Errorf("expected 'unrecognized issuer' found :%v", err)
		}
	})
}

func TestNoneAlgorithmAttack(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss":  testMgr.Issuer,
		"data": UserClaims{ID: 99},
	})

	unsignedToken, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, err := ParseToken[UserClaims](testMgr, unsignedToken)
	if err == nil {
		t.Error("Security Vulnerability: Accepted token with 'none' algorithm!")
	}
}
