package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/jwtauth/v5"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/term"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rhpds/sandbox/internal/models"
)

func main() {
	// ---------------------------------------------------------------------
	// Open connection to postgresql
	// ---------------------------------------------------------------------

	// Get connection info from environment variables

	if os.Getenv("DATABASE_URL") == "" {
		fmt.Println("DATABASE_URL environment variable not set")
		os.Exit(1)
	}
	connStr := os.Getenv("DATABASE_URL")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbPool, err := pgxpool.Connect(context.Background(), connStr)
	if err != nil {
		panic(err)
	}
	defer dbPool.Close()
	// ---------------------------------------------------------------------
	bytepw := []byte(os.Getenv("JWT_AUTH_SECRET"))
	if len(bytepw) == 0 {
		fmt.Print("JWT Auth secret: ")
		var err error
		bytepw, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			os.Exit(1)
		}
	}

	pw := strings.Trim(string(bytepw), "\r\n\t ")
	fmt.Println("Enter Claims in the JSON format:")
	fmt.Println(`for example: {"kind": "login", "name": "gucore", "role": "admin"}`)
	claims, err := io.ReadAll(os.Stdin)

	// json unmarshal claims

	var claimsMap map[string]interface{}
	json.Unmarshal([]byte(claims), &claimsMap)

	// set 'iat'
	jwtauth.SetIssuedNow(claimsMap)
	// set 'exp' to 10y by default
	if _, ok := claimsMap["exp"]; !ok {
		jwtauth.SetExpiryIn(claimsMap, time.Hour*24*365*10)
	}

	// Save token in DB
	token, err := models.CreateToken(claimsMap)
	if err != nil {
		panic(err)
	}

	id, err := token.Save(dbPool)
	if err != nil {
		panic(err)
	}

	claimsMap["jti"] = strconv.Itoa(id)

	tokenAuth := jwtauth.New("HS256", []byte(pw), nil)
	_, tokenString, _ := tokenAuth.Encode(claimsMap)
	fmt.Printf("token:\n%s\n", tokenString)
}
