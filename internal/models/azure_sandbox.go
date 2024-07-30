package models

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v4"
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

	Credentials []any                 `json:"credentials"`
	Provider    *AzureSandboxProvider `json:"-"`
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

func (a *AzureSandboxProvider) Request(
	serviceUuid string,
	annotations Annotations,
) (AzureSandboxWithCreds, error) {
	azureSandbox := AzureSandboxWithCreds{
		AzureSandbox: AzureSandbox{
			SubscriptionId: "pool-00-31",
			Name:           "sandbox",
			Kind:           "AzureSandbox",
			ServiceUuid:    serviceUuid,
			Annotations:    annotations,
			Status:         "initializing",
		},
		Provider: a,
	}

	err := azureSandbox.Save()
	if err != nil {
		log.Logger.Error("Error saving Azure sandbox", "error", err)
		return AzureSandboxWithCreds{}, err
	}

	// TODO: Do provisioning....
	//

	azureSandbox.Status = "success"
	err = azureSandbox.Save()
	if err != nil {
		log.Logger.Error("Can't update Azure Sandbox status", "error", err)
		return AzureSandboxWithCreds{}, err
	}

	return azureSandbox, nil
}

func (a *AzureSandboxProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]AzureSandboxWithCreds, error) {
	sandboxes := []AzureSandboxWithCreds{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
			resource_data,
			id,
			resource_name,
			resource_type,
			status,
			cleanup_count,
			pgp_sym_decrypt(resource_credentials, $2)
		FROM
			resources
		WHERE service_uuid = $1 AND resource_type = 'AzureSandbox'`,
		serviceUuid, a.VaultSecret,
	)
	if err != nil {
		fmt.Printf("\n\nSQL error: %s\n\n", err)
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found", "service_uuid", serviceUuid)
		}
		return sandboxes, err
	}

	for rows.Next() {
		var sandbox AzureSandboxWithCreds

		creds := ""
		if err := rows.Scan(
			&sandbox,
			&sandbox.Id,
			&sandbox.Name,
			&sandbox.Kind,
			&sandbox.Status,
			&sandbox.CleanupCount,
			&creds,
		); err != nil {
			return sandboxes, err
		}

		// Unmarshal creds into account.Credentials
		if err := json.Unmarshal([]byte(creds), &sandbox.Credentials); err != nil {
			return sandboxes, err
		}

		sandbox.ServiceUuid = serviceUuid

		sandboxes = append(sandboxes, sandbox)
	}

	return sandboxes, nil
}

func (a *AzureSandboxProvider) Release(serviceUuid string) error {
	sandboxes, err := a.FetchAllByServiceUuidWithCreds(serviceUuid)
	if err != nil {
		return err
	}

	var errorHappened error

	for _, sandbox := range sandboxes {
		//		if sandbox.Status != "error" &&
		//			sandbox.Status != "scheduling" &&
		//			sandbox.Status != "initializing" {
		//			// If the sandbox is not in error and the namespace is empty, throw an error
		//			errorHappened = fmt.Errorf("azure sandbox state is not valid for delete")
		//			log.Logger.Error("Azure Sandbox state is not valid for delete", "error", sandbox)
		//			continue
		//		}
		//
		sandbox.Provider = a
		if err := sandbox.Delete(); err != nil {
			errorHappened = err
			continue
		}
	}
	return errorHappened
}

func (sb *AzureSandboxWithCreds) Update() error {
	if sb.Id == 0 {
		return fmt.Errorf("failed to update resources, Id is not set")
	}

	credentials, err := json.Marshal(sb.Credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	sb.Credentials = []any{}

	_, err = sb.Provider.DbPool.Exec(
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
		sb.Provider.VaultSecret,
		sb.Status,
		sb.CleanupCount,
		sb.Id,
	)
	if err != nil {
		return fmt.Errorf("failed to update resource: %w", err)
	}

	return nil
}

func (sb *AzureSandboxWithCreds) Save() error {
	if sb.Id != 0 {
		return sb.Update()
	}

	credentials, err := json.Marshal(sb.Credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	sb.Credentials = []any{}

	err = sb.Provider.DbPool.QueryRow(
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
		sb.Provider.VaultSecret,
		sb.Status,
		sb.CleanupCount,
	).Scan(&sb.Id)
	if err != nil {
		return fmt.Errorf("failed to insert resource: %w", err)
	}

	return nil
}

// models.Deletable interface implementation
func (sb *AzureSandboxWithCreds) Delete() error {
	fmt.Printf("\n\nSandbox: %s (%d) for deletion!\n\n", sb.Name, sb.Id)

	// TODO: Implement cleanup here
	_, err := sb.Provider.DbPool.Exec(
		context.Background(),
		`DELETE FROM resources WHERE id = $1`,
		sb.Id,
	)
	if err != nil {
		return fmt.Errorf("faild to remove resource: %w", err)
	}

	return nil
}
