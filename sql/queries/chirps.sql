-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
           gen_random_uuid(),
           NOW(),
           NOW(),
           $1,
           $2
       )
RETURNING *;

-- name: GetChirps :many
SELECT * FROM chirps
WHERE (author_id = $1 OR $1 IS NULL)
ORDER BY created_at ${2};

-- name: GetChirp :one
SELECT * FROM chirps
WHERE chirps.id = $1;

-- name: DeleteChirp :one
DELETE FROM chirps
WHERE id = $1
RETURNING id;

-- name: GetChirpUserID :one
SELECT user_id FROM chirps
WHERE id = $1;