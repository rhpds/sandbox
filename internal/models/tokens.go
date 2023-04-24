package models

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
)

type Token struct {
	Model

	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Role       string    `json:"role"`
	Iat        int64     `json:"iat"`
	Exp        int64     `json:"exp"`
	Expiration time.Time `json:"expiration"`
	Valid      bool      `json:"valid"`
}

func CreateToken(claims map[string]any) (Token, error) {
	kind, ok := claims["kind"].(string)
	if !ok {
		return Token{}, fmt.Errorf("invalid kind in claims")
	}

	name, ok := claims["name"].(string)
	if !ok {
		return Token{}, fmt.Errorf("invalid name in claims")
	}
	iat, ok := claims["iat"].(int64)
	if !ok {
		return Token{}, fmt.Errorf("invalid iat in claims")
	}

	exp, ok := claims["exp"].(int64)
	if !ok {
		return Token{}, fmt.Errorf("invalid exp in claims")
	}

	role, ok := claims["role"].(string)
	if !ok {
		return Token{}, fmt.Errorf("invalid role in claims")
	}

	return Token{
		Kind:       kind,
		Name:       name,
		Role:       role,
		Iat:        iat,
		Exp:        exp,
		Expiration: time.Unix(exp, 0),
		Valid:      true,
	}, nil
}

func (t Token) Save(dbpool *pgxpool.Pool) (id int, err error) {
	err = dbpool.QueryRow(context.Background(), `
		INSERT INTO tokens (kind, name, role, iat, exp, expiration, valid)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		t.Kind, t.Name, t.Role, t.Iat, t.Exp, t.Expiration, t.Valid).Scan(&id)
	if err != nil {
		return 0, err
	}

	return id, nil
}

// Invalidate the token
func (t Token) Invalidate(dbpool *pgxpool.Pool) error {
	_, err := dbpool.Exec(context.Background(), `
		UPDATE tokens SET valid = false WHERE id = $1`,
		t.ID)
	if err != nil {
		return err
	}

	return nil
}

type Tokens []Token

func (t *Tokens) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func FetchAllTokens(dbpool *pgxpool.Pool) (Tokens, error) {
	rows, err := dbpool.Query(context.Background(), `
		SELECT id, kind, name, role, iat, exp, expiration, created_at, updated_at, valid
		FROM tokens
	`)
	if err != nil {
		return []Token{}, err
	}
	defer rows.Close()

	tokens := []Token{}

	for rows.Next() {
		var t Token
		err = rows.Scan(&t.ID, &t.Kind, &t.Name, &t.Role, &t.Iat, &t.Exp, &t.Expiration, &t.CreatedAt, &t.UpdatedAt, &t.Valid)
		if err != nil {
			return []Token{}, err
		}

		tokens = append(tokens, t)
	}

	return tokens, nil
}

func FetchTokenById(dbpool *pgxpool.Pool, id int) (Token, error) {
	var t Token
	err := dbpool.QueryRow(context.Background(), `
		SELECT id, kind, name, role, iat, exp, expiration, created_at, updated_at, valid
		FROM tokens
		WHERE id = $1
	`, id).Scan(&t.ID, &t.Kind, &t.Name, &t.Role, &t.Iat, &t.Exp, &t.Expiration, &t.CreatedAt, &t.UpdatedAt, &t.Valid)
	if err != nil {
		return Token{}, err
	}

	return t, nil
}
