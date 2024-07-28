package models

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
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
	Id             int         `json:"id,omitempty"`
	Name           string      `json:"name"`
	Kind           string      `json:"kind"` // AzureSandbox
	ServiceUuid    string      `json:"service_uuid"`
	Status         string      `json:"status"`
	CleanupCount   int         `json:"cleanup_count"`
	SubscriptionId string      `json:"subscription_id"`
	Annotations    Annotations `json:"annotations"`
	ToCleanup      bool        `json:"to_cleanup"`
}

func NewAzureSandboxProvider(
	dbPool *pgxpool.Pool,
	vaultSecret string,
) AzureSandboxProvider {
	return AzureSandboxProvider{
		DbPool:      dbPool,
		VaultSecret: vaultSecret,
	}
}

func (a *AzureSandboxProvider) Update(sb AzureSandboxWithCreds) error {
	if sb.Id == 0 {
		return fmt.Errorf("failed to update resources, Id is not set")
	}

	credentials, err := json.Marshal(sb.Credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	sb.Credentials = []any{}

	_, err = a.DbPool.Exec(
		context.Background(),
		`UPDATE resources
		SET resource_name = $1,
			resource_type = $2,
			service_uuid = $3,
			resource_data = $4,
			resource_credentials = pgp_sym_encrypt($5::text, $6),
			status = $7,
			cleanup_count = $8
		WHERE id = $9`,
		sb.Name,
		sb.Kind,
		sb.ServiceUuid,
		sb,
		credentials,
		a.VaultSecret,
		sb.Status,
		sb.CleanupCount,
		sb.Id,
	)
	if err != nil {
		return fmt.Errorf("failed to update resource: %w", err)
	}

	return nil
}

func (a *AzureSandboxProvider) Save(sb AzureSandboxWithCreds) (int, error) {
	if sb.Id != 0 {
		return sb.Id, a.Update(sb)
	}

	credentials, err := json.Marshal(sb.Credentials)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal credentials: %w", err)
	}

	sb.Credentials = []any{}

	var id int
	err = a.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO resources
		(resource_name, resource_type, service_uuid, to_cleanup, resource_data, resource_credentials, status, cleanup_count)
		VALUES ($1, $2, $3, $4, $5, pgp_sym_encrypt($6::text, $7), $8, $9) RETURNING id`,
		sb.Name,
		sb.Kind,
		sb.ServiceUuid,
		sb.ToCleanup,
		sb,
		credentials,
		a.VaultSecret,
		sb.Status,
		sb.CleanupCount,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("failed to insert resource: %w", err)
	}

	return id, nil
}

func (a *AzureSandboxProvider) Request(
	serviceUuid string,
	count int,
	annotations Annotations,
) ([]AzureSandboxWithCreds, error) {

	// TODO: Implement the multiple sandbox creation logic
	azureSandboxList := make([]AzureSandboxWithCreds, count)

	for i := 0; i < count; i++ {
		azureSandboxList[i] = AzureSandboxWithCreds{
			AzureSandbox: AzureSandbox{
				SubscriptionId: fmt.Sprintf("pool-00-31%d", i),
				Name:           fmt.Sprintf("sandbox-%d", i),
				Kind:           "AzureSandbox",
				ServiceUuid:    serviceUuid,
				Annotations:    annotations,
				Status:         "initializing",
			},
		}

		_, err := a.Save(azureSandboxList[i])
		if err != nil {
			log.Logger.Error("Error saving Azure sandbox", "error", err)
			return nil, err
		}
	}

	return azureSandboxList, nil
}

// models.Deletable interface implementation
func (sandbox *AzureSandbox) Delete() error {
	return nil
}
