package models

import (
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
)

// TODO: Check if sturct's fields are used
type AzureSandboxProvider struct {
	DbPool      *pgxpool.Pool
	VaultSecret string
}

type AzureSandbox struct {
	SubscriptionId string
}

func NewAzureSandboxProvider(dbPool *pgxpool.Pool, vaultSecret string) *AzureSandboxProvider {
	return &AzureSandboxProvider{
		DbPool:      dbPool,
		VaultSecret: vaultSecret,
	}
}

func (a *AzureSandboxProvider) Request(serviceUuid string, annotations map[string]string) (AzureSandbox, error) {
	fmt.Println("\n\n\nRequesting Azure Sandbox called.\n\n\n")
	return AzureSandbox{
		SubscriptionId: "pool-00-315",
	}, nil
}

// models.Deletable interface implementation
func (sandbox *AzureSandbox) Delete() error {
	return nil
}
