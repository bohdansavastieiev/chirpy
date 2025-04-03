package main

import (
	"github.com/bohdansavastieiev/chirpy/internal/database"
	"github.com/google/uuid"
	"sync/atomic"
	"time"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	platform       string
	dbQueries      *database.Queries
	secret         string
	expirationJWT  time.Duration
	polkaKey       string
}

type BaseUserResponse struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

type ChirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type LoginUserResponse struct {
	BaseUserResponse
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}
