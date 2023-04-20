package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/jwtauth/v5"
	"golang.org/x/term"
	"io"
	"os"
	"strings"
	"syscall"
)

func main() {
	fmt.Print("JWT Auth secret: ")
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}

	pw := strings.Trim(string(bytepw), "\r\n\t ")
	fmt.Println("Enter Claims in the JSON format:")
	fmt.Println(`for example: {"kind": "login", "name": "gucore", "role": "admin"}`)
	claims, err := io.ReadAll(os.Stdin)

	// json unmarshal claims

	var claimsMap map[string]interface{}
	json.Unmarshal([]byte(claims), &claimsMap)

	tokenAuth := jwtauth.New("HS256", []byte(pw), nil)
	_, tokenString, _ := tokenAuth.Encode(claimsMap)
	fmt.Printf("token:\n%s\n", tokenString)
}
