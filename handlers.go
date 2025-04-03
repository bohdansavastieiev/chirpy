package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bohdansavastieiev/chirpy/internal/auth"
	"github.com/bohdansavastieiev/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"log"
	"net/http"
	"net/mail"
	"sort"
	"strings"
	"time"
)

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if _, err := w.Write(response); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func validateChirpBody(chirpBody string) (string, error) {
	if chirpLen := len(chirpBody); chirpLen > 140 {
		return "", fmt.Errorf("chirp is too long: %v", chirpLen)
	}

	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	wordsInLower := strings.Split(chirpBody, " ")
	var cleanedWords []string
	for _, word := range wordsInLower {
		var isProfane bool
		for _, profaneWord := range profaneWords {
			if strings.ToLower(word) == profaneWord {
				cleanedWords = append(cleanedWords, "****")
				isProfane = true
				break
			}
		}
		if !isProfane {
			cleanedWords = append(cleanedWords, word)
		} else {
			isProfane = false
		}
	}

	return strings.Join(cleanedWords, " "), nil
}

/////////////////////////
/// Specific handlers ///
/////////////////////////

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("OK"))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1>"+
		"<p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits.Load())))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, _ *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "This action can only be done in the development environment")
		return
	}

	err := cfg.dbQueries.DeleteUsers(context.Background())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	cfg.fileserverHits.Swap(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("Error closing request body: %v", err)
		}
	}()

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var reqBody requestBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(reqBody.Email))
	if _, err := mail.ParseAddress(normalizedEmail); err != nil {
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}
	hashedPassword, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}

	user, err := cfg.dbQueries.CreateUser(context.Background(), database.CreateUserParams{
		Email:          normalizedEmail,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			respondWithError(w, http.StatusConflict, "User with this email already exists")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Couldn't create user")
		return
	}

	respondWithJSON(w, http.StatusCreated, BaseUserResponse{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authorization failed")
	}

	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authorization failed")
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("Error closing request body: %v", err)
		}
	}()

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var reqBody requestBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(reqBody.Email))
	if _, err := mail.ParseAddress(normalizedEmail); err != nil {
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}
	hashedPassword, err := auth.HashPassword(reqBody.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}

	user, err := cfg.dbQueries.UpdateUser(context.Background(), database.UpdateUserParams{
		ID:             userID,
		Email:          normalizedEmail,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			respondWithError(w, http.StatusConflict, "User with this email already exists")
			return
		}
		log.Printf("unexpected error occurred: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	respondWithJSON(w, http.StatusOK, BaseUserResponse{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func (cfg *apiConfig) markUserChirpyRedHandler(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "You are not authorized to perform this action")
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("Error closing request body: %v", err)
		}
	}()

	type requestBody struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	var reqBody requestBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}

	w.Header().Set("Content-type", "application/json")
	if reqBody.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	_, err = cfg.dbQueries.MakeUserChirpyRed(context.Background(), reqBody.Data.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "User with this ID doesn't exist")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authorization token was not provided")
		return
	}

	userIDFromToken, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication failed")
		return
	}

	type requestBody struct {
		Body string `json:"body"`
	}

	var reqBody requestBody
	defer func() {
		if r.Body != nil {
			if err := r.Body.Close(); err != nil {
				log.Printf("Error closing request body: %v", fmt.Errorf("closing request body: %w", err))
			}
		}
	}()
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		log.Printf("Error decoding the request body: %v", err)
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}

	cleanBody, err := validateChirpBody(reqBody.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Request did not pass validation rules: %v", err))
		return
	}

	chirp, err := cfg.dbQueries.CreateChirp(context.Background(), database.CreateChirpParams{Body: cleanBody, UserID: userIDFromToken})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create a chirp")
		return
	}

	respondWithJSON(w, http.StatusCreated, ChirpResponse{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	sortOrder := strings.ToLower(r.URL.Query().Get("sort"))
	if sortOrder != "asc" && sortOrder != "desc" && sortOrder != "" {
		respondWithError(w, http.StatusBadRequest, "Invalid sort value")
		return
	}

	var chirps []database.Chirp
	var err error
	authorIDString := r.URL.Query().Get("author_id")
	if authorIDString == "" {
		chirps, err = cfg.dbQueries.GetChirps(context.Background())
	} else {
		authorID, err := uuid.Parse(authorIDString)
		if err != nil {
			respondWithJSON(w, http.StatusOK, []ChirpResponse{})
			return
		}
		chirps, err = cfg.dbQueries.GetChirpsByAuthor(context.Background(), authorID)
	}
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
	}

	if sortOrder == "desc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		})
	}

	var chirpsRes []ChirpResponse
	for _, chirp := range chirps {
		chirpsRes = append(chirpsRes, ChirpResponse{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	}

	respondWithJSON(w, http.StatusOK, chirpsRes)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID format")
		return
	}

	chirp, err := cfg.dbQueries.GetChirp(context.Background(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "Chirp with this ID doesn't exist")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	respondWithJSON(w, http.StatusOK, ChirpResponse{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID format")
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authorization token was not provided")
		return
	}

	userIDFromToken, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication failed")
		return
	}

	chirpUserID, err := cfg.dbQueries.GetChirpUserID(context.Background(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "Chirp with this ID doesn't exist")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	if chirpUserID != userIDFromToken {
		log.Printf("Unauthorized attempt to delete chirp by user %s", userIDFromToken)
		respondWithError(w, http.StatusForbidden, "You have no permissions to perform this action")
		return
	}

	deletedChirpID, err := cfg.dbQueries.DeleteChirp(context.Background(), id)
	if err != nil || deletedChirpID != id {
		log.Printf("Unexpected error. DeletedChirpID: %v, error: %v", deletedChirpID, err)
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("Error closing request body: %v", err)
		}
	}()

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var reqBody requestBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		log.Printf("Error decoding a request body")
		respondWithError(w, http.StatusBadRequest, "Request body is in invalid format")
		return
	}

	user, err := cfg.dbQueries.GetUser(context.Background(), reqBody.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Credentials are invalid")
		return
	}

	err = auth.CheckPasswordHash(user.HashedPassword, reqBody.Password)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Credentials are invalid")
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.secret, cfg.expirationJWT)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	refreshTokenDB, err := cfg.dbQueries.CreateRefreshToken(context.Background(), database.CreateRefreshTokenParams{
		Token:  refreshToken,
		UserID: user.ID,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	respondWithJSON(w, http.StatusOK, LoginUserResponse{
		BaseUserResponse: BaseUserResponse{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
		},
		Token:        token,
		RefreshToken: refreshTokenDB.Token,
	})
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Refresh Token is invalid")
		return
	}

	refreshTokenDB, err := cfg.dbQueries.GetRefreshToken(context.Background(), refreshToken)
	if err != nil || refreshTokenDB.ExpiresAt.Before(time.Now()) || refreshTokenDB.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "Refresh Token is invalid")
		return
	}

	newJWT, err := auth.MakeJWT(refreshTokenDB.UserID, cfg.secret, cfg.expirationJWT)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	type refreshTokenResponse struct {
		Token string `json:"token"`
	}
	respondWithJSON(w, http.StatusOK, refreshTokenResponse{
		Token: newJWT,
	})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Refresh Token is invalid")
		return
	}

	refreshTokenDB, err := cfg.dbQueries.GetRefreshToken(context.Background(), refreshToken)
	if err != nil || refreshTokenDB.ExpiresAt.Before(time.Now()) || refreshTokenDB.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "Refresh Token is invalid")
		return
	}

	if err = cfg.dbQueries.RevokeToken(context.Background(), refreshTokenDB.Token); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
}
