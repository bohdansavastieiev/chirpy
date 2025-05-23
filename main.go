package main

import (
	"database/sql"
	"github.com/bohdansavastieiev/chirpy/internal/database"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("environment variables were not loaded successfully")
	}
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")
	polkaKey := os.Getenv("POLKA_KEY")
	if dbURL == "" || platform == "" || secret == "" || polkaKey == "" {
		log.Fatal("environment variables were not loaded successfully")
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatal("connection to the database is not successful")
	}
	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
		platform:       platform,
		dbQueries:      database.New(db),
		secret:         secret,
		expirationJWT:  3600 * time.Second,
		polkaKey:       polkaKey,
	}

	const filepathRoot = "."
	const port = "8080"

	mux := http.NewServeMux()
	strippedFileServer := http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))
	mux.Handle("GET /app/", apiCfg.middlewareMetricsInc(strippedFileServer))
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.markUserChirpyRedHandler)

	srv := http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}
