package internal

import (
	"strings"
	"testing"
)

func TestDefaultPasswordHasher_HashAndVerify(t *testing.T) {
	hasher := &DefaultPasswordHasher{}
	password := "test-secure-password-123"

	// Test successful hahshing
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Test format validation
	if !strings.HasPrefix(hash, "$argon2id") {
		t.Errorf("Hash format is incorrect, got: %s", hash)
	}

	// Test successful verification
	if !hasher.Verify(password, hash) {
		t.Errorf("verification failed for the correct password")
	}

	// Test fail for incorrect password
	if hasher.Verify("test-secure-password-124", hash) {
		t.Errorf("verification succeeded for wrong password")
	}
}

func TestDefaultPasswordHasher_Uniqueness(t *testing.T) {
	hasher := &DefaultPasswordHasher{}
	password := "samepassword"

	hash1, _ := hasher.Hash(password)
	hash2, _ := hasher.Hash(password)

	if hash1 == hash2 {
		t.Errorf("Hashing the same password twice produced the identical hashes (salt is not unique)")
	}
}

func TestDefaultPasswordHasher_MalformedHash(t *testing.T) {
	hasher := &DefaultPasswordHasher{}
	password := "test-password-123"

	invalidHashes := []string{
		"not a hash", //not  a hash
		"$argon2id$v=19$m=65536,t=2,p=4$short$hash", //invalid base64
		"$argon2i$v=19$m=65536,t=2,p=4$salt$hash",   // wrong argon variant (Argon 2i)
	}

	for _, v := range invalidHashes {
		if hasher.Verify(password, v) {
			t.Errorf("validation should have failed for malformed hash: %s", v)
		}
	}
}

func BenchmarkHasher(b *testing.B) {
	hasher := &DefaultPasswordHasher{}
	password := "benchmark-password"

	for i := 0; i < b.N; i++ {
		_, _ = hasher.Hash(password)
	}
}
