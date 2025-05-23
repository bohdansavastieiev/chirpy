# Chirpy

A Twitter-like REST API service built with Go that allows users to post short messages ("chirps"), manage their accounts, and interact with a premium subscription service.

## Features

- User authentication with JWT tokens
- CRUD operations for chirps (messages)
- Content moderation for chirps
- Premium user features (Chirpy Red)
- File serving capabilities
- Admin metrics and controls

## Prerequisites

- Go 1.24.1
- PostgreSQL database
- Environment variables (see `.env.example`)

## API Endpoints

### Authentication
- `POST /api/users` - Create new user
- `PUT /api/users` - Update user
- `POST /api/login` - User login
- `POST /api/refresh` - Refresh JWT token
- `POST /api/revoke` - Revoke refresh token

### Chirps
- `GET /api/chirps` - List all chirps
- `GET /api/chirps/{chirpID}` - Get specific chirp
- `POST /api/chirps` - Create new chirp
- `DELETE /api/chirps/{chirpID}` - Delete chirp

### Admin
- `GET /admin/metrics` - View metrics
- `POST /admin/reset` - Reset application state (dev only)

### Other
- `GET /api/healthz` - Health check
- `POST /api/polka/webhooks` - Premium subscription webhook

## Running the Application

1. Copy `.env.example` to `.env` and configure variables
2. Start PostgreSQL database
3. Run the application:
   ```bash
   go run .
   ```
   The server will start on port 8080.