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

type AzureSandboxWithCreds struct {
	AzureSandbox

	Credentials []any `json:"credentials"`
}

type AzureSandbox struct {
	SubscriptionId string      `json:"subscription_id"`
	Annotations    Annotations `json:"annotations"`
}

func NewAzureSandboxProvider(dbPool *pgxpool.Pool, vaultSecret string) AzureSandboxProvider {
	return AzureSandboxProvider{
		DbPool:      dbPool,
		VaultSecret: vaultSecret,
	}
}

func (a *AzureSandboxProvider) Request(serviceUuid string, count int, annotations Annotations) ([]AzureSandboxWithCreds, error) {

	// TODO: Implement the multiple sandbox creation logic
	azureSandboxList := make([]AzureSandboxWithCreds, count)

	for i := 0; i < count; i++ {
		azureSandboxList[i] = AzureSandboxWithCreds{
			AzureSandbox: AzureSandbox{
				SubscriptionId: fmt.Sprintf("pool-00-31%d", i),
				Annotations:    annotations,
			},
		}
	}

	return azureSandboxList, nil
}

// models.Deletable interface implementation
func (sandbox *AzureSandbox) Delete() error {
	return nil
}
