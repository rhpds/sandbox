package graph

//go:generate go run github.com/99designs/gqlgen generate

import (
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/models"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	DbPool      *pgxpool.Pool
	AwsProvider models.AwsAccountProvider
	OcpProvider models.OcpSandboxProvider
	DnsProvider models.DNSSandboxProvider
	IbmProvider models.IBMResourceGroupSandboxProvider
}
