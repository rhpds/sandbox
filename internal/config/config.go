package config

import (
	"github.com/matoous/go-nanoid/v2"
)

// Generate a unique ID to identify this process
var LocalityID string

func init() {
	LocalityID, _ = gonanoid.New()
}
