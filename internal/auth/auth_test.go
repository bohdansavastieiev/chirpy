package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

func TestHashPassword(t *testing.T) {
	password := "testPassword123"
	hash, err := HashPassword(password)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, password, hash)
}

func TestCheckPasswordHash(t *testing.T) {
	password := "password"
	hash, err := HashPassword(password)
	assert.NoError(t, err)

	testCases := []struct {
		name     string
		hash     string
		password string
		wantErr  bool
	}{
		{"Correct hash", hash, "password", false},
		{"Incorrect hash", hash, "another_password", true},
		{"Empty hash", "", "password", true},
		{"Empty password", "$2a$10$valid-hash", "", true},
		{"Invalid hash format", "invalid-hash", "password", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPasswordHash(tc.hash, tc.password)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "secret"
	expiresIn := 24 * time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestMakeJWT_InvalidExpiresIn_ReturnsError(t *testing.T) {
	userID := uuid.New()
	validSecret := "secret"

	_, err := MakeJWT(userID, validSecret, 0*time.Second)
	assert.Error(t, err)

	_, err = MakeJWT(userID, validSecret, -1*time.Second)
	assert.Error(t, err)
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	validSecret := "secret"
	expiresIn := 24 * time.Hour
	token, err := MakeJWT(userID, validSecret, expiresIn)
	assert.NoError(t, err)

	retrievedUserID, err := ValidateJWT(token, validSecret)
	assert.NoError(t, err)
	assert.Equal(t, userID, retrievedUserID)
}

func TestValidateJWT_WhenExpired_ReturnsError(t *testing.T) {
	userID := uuid.New()
	validSecret := "secret"

	expiredClaims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
	}

	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	tokenString, err := expiredToken.SignedString([]byte(validSecret))
	assert.NoError(t, err)

	retrievedUserID, err := ValidateJWT(tokenString, validSecret)

	assert.Error(t, err)
	assert.Equal(t, uuid.UUID{}, retrievedUserID)
}

func TestValidateJWT_WithIncorrectSecret_ReturnsError(t *testing.T) {
	userID := uuid.New()
	validSecret := "secret"
	expiresIn := 24 * time.Hour
	token, err := MakeJWT(userID, validSecret, expiresIn)
	assert.NoError(t, err)

	retrievedUserID, err := ValidateJWT(token, "new_secret")
	assert.Error(t, err)
	assert.Equal(t, uuid.UUID{}, retrievedUserID)
}

func TestValidateJWT_WithInvalidToken_ReturnsError(t *testing.T) {
	validSecret := "secret"

	retrievedUserID, err := ValidateJWT("", validSecret)
	assert.Error(t, err)
	assert.Equal(t, uuid.UUID{}, retrievedUserID)

	retrievedUserID, err = ValidateJWT("token", validSecret)
	assert.Error(t, err)
	assert.Equal(t, uuid.UUID{}, retrievedUserID)

	retrievedUserID, err = ValidateJWT("token.token", validSecret)
	assert.Error(t, err)
	assert.Equal(t, uuid.UUID{}, retrievedUserID)

	retrievedUserID, err = ValidateJWT("token.token.token", validSecret)
	assert.Error(t, err)
	assert.Equal(t, uuid.UUID{}, retrievedUserID)
}

func TestGetBearerToken(t *testing.T) {
	header := "Bearer jwt"
	expectedToken := "jwt"
	headers := http.Header{}
	headers.Set("Authorization", header)

	token, err := GetBearerToken(headers)

	assert.NoError(t, err)
	assert.Equal(t, token, expectedToken)
}

func TestGetBearerToken_ReturnsError(t *testing.T) {
	token, err := GetBearerToken(http.Header{})
	assert.Error(t, err)
	assert.Equal(t, "", token)

	expectedToken := "jwt"
	headers := http.Header{}
	headers.Set("Authorization", expectedToken)
	token, err = GetBearerToken(http.Header{})
	assert.Error(t, err)
	assert.Equal(t, "", token)
}
