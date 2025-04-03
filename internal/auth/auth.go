package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		return "", errors.New("error occurred during generating hash from a password")
	}
	return string(hash), nil
}

func CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, secret string, expiresIn time.Duration) (string, error) {
	if expiresIn <= 0 {
		return "", errors.New("expiresIn must be a positive duration")
	}

	timeNow := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(timeNow),
		ExpiresAt: jwt.NewNumericDate(timeNow.Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(tokenSecret), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return uuid.UUID{}, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return uuid.UUID{}, errors.New("JWT is invalid")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.UUID{}, err
	}

	return userID, nil
}

func MakeRefreshToken() (string, error) {
	randomData := make([]byte, 32)
	_, _ = rand.Read(randomData)
	refreshToken := hex.EncodeToString(randomData)
	return refreshToken, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	return GetAuthHeader(headers, "Bearer")
}

func GetAPIKey(headers http.Header) (string, error) {
	return GetAuthHeader(headers, "ApiKey")
}

func GetAuthHeader(headers http.Header, authPrefix string) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header was not found")
	}

	if !strings.HasPrefix(authHeader, authPrefix+" ") {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimPrefix(authHeader, authPrefix+" ")
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("token is missing")
	}

	return token, nil
}
