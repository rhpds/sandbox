package models

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/api/azure"
	"github.com/rhpds/sandbox/internal/log"
)

const (
	projectTagPrefix = "sandbox-"
	azurePoolId      = "01"

	poolPrefix = "pool-01-"
	poolSize   = 10
)

type AzureSandboxProvider struct {
	DbPool      *pgxpool.Pool
	VaultSecret string

	azureTenantId      string
	azureClientId      string
	azureSecret        string
	azurePoolApiSecret string
}

type AzureSandboxWithCreds struct {
	AzureSandbox

	Credentials []any                 `json:"credentials"`
	Provider    *AzureSandboxProvider `json:"-"`
}

type AzureSandbox struct {
	Id                int         `json:"id,omitempty"`
	Name              string      `json:"name"`
	Kind              string      `json:"kind"` // AzureSandbox
	ServiceUuid       string      `json:"service_uuid"`
	Status            string      `json:"status"`
	CleanupCount      int         `json:"cleanup_count"`
	Annotations       Annotations `json:"annotations"`
	ToCleanup         bool        `json:"to_cleanup"`
	SubscriptionName  string      `json:"subscription_name"`
	SubscriptionId    string      `json:"subscription_id"`
	ResourceGroupName string      `json:"resource_group_name"`
	AppID             string      `json:"app_id"`
	DisplayName       string      `json:"display_name"`
}

func NewAzureSandboxProvider(
	dbPool *pgxpool.Pool,
	vaultSecret string,
) (AzureSandboxProvider, error) {
	provider := AzureSandboxProvider{
		DbPool:      dbPool,
		VaultSecret: vaultSecret,
	}

	if provider.azureTenantId = os.Getenv("AZURE_TENANT_ID"); provider.azureTenantId == "" {
		return AzureSandboxProvider{}, fmt.Errorf("AZURE_TENANT_ID is not set")
	}

	if provider.azureClientId = os.Getenv("AZURE_CLIENT_ID"); provider.azureClientId == "" {
		return AzureSandboxProvider{}, fmt.Errorf("AZURE_CLIENT_ID is not set")
	}

	if provider.azureSecret = os.Getenv("AZURE_SECRET"); provider.azureSecret == "" {
		return AzureSandboxProvider{}, fmt.Errorf("AZURE_SECRET is not set")
	}

	if provider.azurePoolApiSecret = os.Getenv("AZURE_POOL_API_SECRET"); provider.azurePoolApiSecret == "" {
		return AzureSandboxProvider{}, fmt.Errorf("AZURE_POOL_API_SECRET is not set")
	}

	return provider, nil
}

func (a *AzureSandboxProvider) Request(
	serviceUuid string,
	annotations Annotations,
) (AzureSandboxWithCreds, error) {

	// TODO: What name should be created for the sanbox?
	sandboxName := fmt.Sprintf("%04d", rand.Intn(900))

	azureSandbox := AzureSandboxWithCreds{
		AzureSandbox: AzureSandbox{
			//			SubscriptionId: "pool-00-31",
			Name:        sandboxName,
			Kind:        "AzureSandbox",
			ServiceUuid: serviceUuid,
			Annotations: annotations,
			Status:      "initializing",
		},
		Provider: a,
	}

	err := azureSandbox.Save()
	if err != nil {
		log.Logger.Error("Error saving Azure sandbox", "error", err)
		return AzureSandboxWithCreds{}, err
	}

	// Create the sandbox asynchronously
	go azureSandbox.Create()

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

// TODO: Are we removing sandboxes in "error" state?
func (a *AzureSandboxProvider) Release(serviceUuid string) error {
	sandboxes, err := a.FetchAllByServiceUuidWithCreds(serviceUuid)
	if err != nil {
		return err
	}

	var errorHappened error

	for _, sandbox := range sandboxes {
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

func (sb *AzureSandboxWithCreds) setStatus(status string) error {
	_, err := sb.Provider.DbPool.Exec(
		context.Background(),
		fmt.Sprintf(`UPDATE resources
			SET status = $1,
			resource_data['status'] = to_jsonb('%s'::text)
			WHERE id = $2`, status),
		status, sb.Id,
	)

	return err
}

// TODO: I think this function should be part of the sb provider
func (sb *AzureSandboxWithCreds) allocatePool() error {
	pool := map[string]bool{}

	// TODO: These names are hard codded and should be stored somewhere
	// at the config file. So, the pool variable should be initialized using
	// configuration, not generate on the fly.
	for i := 1; i <= poolSize; i++ {
		pool[fmt.Sprintf("%s%03d", poolPrefix, i)] = false
	}

	// TODO: Mutex is required here to properly alocate pool
	// sb.mu.Lock()
	// defer sb.mu.Unlock()

	rows, err := sb.Provider.DbPool.Query(
		context.Background(),
		`SELECT resource_data ->> 'subscription_name' FROM resources WHERE status = 'success'`)
	if err != nil {
		return fmt.Errorf("can't get retrieve about allocated pools")
	}
	defer rows.Close()

	allocatedPools := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("illegal pool name retrieved: %w", err)
		}
		allocatedPools = append(allocatedPools, name)
	}
	if err = rows.Err(); err != nil {
		return fmt.Errorf("can't get allocated pool names: %w", err)
	}

	for _, name := range allocatedPools {
		if _, exists := pool[name]; exists {
			pool[name] = true
		} else {
			log.Logger.Warn("Incorrect pool name found", "warning", name)
			continue
		}
	}

	poolName := make([]string, 0, len(pool))
	for k, v := range pool {
		if !v {
			poolName = append(poolName, k)
		}
	}

	if len(poolName) == 0 {
		return fmt.Errorf("no available pools")
	}

	sb.SubscriptionName = poolName[rand.Intn(len(poolName))]
	return sb.Save()
}

// func (sb *AzureSandboxWithCreds) Create() {
// 	// TODO: Implement provisioning here
// 	poolClient := azure.InitPoolClient(
// 		projectTagPrefix+"test", // TODO: Proper project tag
// 		azurePoolId,
// 		sb.Provider.azurePoolApiSecret,
// 	)

// 	var err error
// 	sb.SubscriptionName, err = poolClient.AllocatePool()
// 	if err != nil {
// 		log.Logger.Error("Error allocating Azure sandbox", "error", err)
// 		return // TODO: Set error status
// 	}

// 	sandboxClient := azure.InitSandboxClient(
// 		azure.AzureCredentials{
// 			TenantID: sb.Provider.azureTenantId,
// 			ClientID: sb.Provider.azureClientId,
// 			Secret:   sb.Provider.azureSecret,
// 		},
// 	)

// 	sandboxInfo, err := sandboxClient.CreateSandboxEnvironment(
// 		sb.SubscriptionName,
// 		sb.Annotations["requester"],
// 		sb.Annotations["guid"],
// 		sb.Annotations["cost_center"],
// 		sb.Annotations["domain"],
// 	)
// 	if err != nil {
// 		log.Logger.Error("Error creating Azure sandbox", "error", err)
// 		return // TODO: Set error status
// 	}

// 	// Summary
// 	fmt.Printf("\n\n"+
// 		"Sandbox Info:\n"+
// 		"\tSubscription Name: %s\n"+
// 		"\tSubscription ID: %s\n"+
// 		"\tResource Group Name: %s\n"+
// 		"\tApp ID: %s\n"+
// 		"\tDisplay Name: %s\n"+
// 		"\tPassword: %s\n\n",
// 		sandboxInfo.SubscriptionName,
// 		sandboxInfo.SubscriptionId,
// 		sandboxInfo.ResourceGroupName,
// 		sandboxInfo.AppID,
// 		sandboxInfo.DisplayName,
// 		sandboxInfo.Password,
// 	)

// 	sb.SubscriptionId = sandboxInfo.SubscriptionId
// 	sb.ResourceGroupName = sandboxInfo.ResourceGroupName
// 	sb.AppID = sandboxInfo.AppID
// 	sb.DisplayName = sandboxInfo.DisplayName
// 	sb.Credentials = []any{
// 		map[string]string{
// 			"password": sandboxInfo.Password,
// 		},
// 	}

// 	sb.Status = "success"
// 	err = sb.Save()
// 	if err != nil {
// 		log.Logger.Error("Can't update Azure Sandbox status", "error", err)
// 		return
// 	}
// }

// // models.Deletable interface implementation
// func (sb *AzureSandboxWithCreds) Delete() error {
// 	fmt.Printf("\n\nSandbox: %s (%d) for deletion!\n\n", sb.Name, sb.Id)

// 	// TODO: Implement cleanup here
// 	// Sandbox cleanup can take time, so probably we should run it asynchronously
// 	// at least yielding control and check for delete process complete periodically
// 	// if it possible via API

// 	sandboxClient := azure.InitSandboxClient(
// 		azure.AzureCredentials{
// 			TenantID: sb.Provider.azureTenantId,
// 			ClientID: sb.Provider.azureClientId,
// 			Secret:   sb.Provider.azureSecret,
// 		},
// 	)

// 	err := sandboxClient.CleanupSandboxEnvironment(
// 		sb.SubscriptionName,
// 		sb.Annotations["guid"],
// 	)
// 	if err != nil {
// 		log.Logger.Error("Error cleaning up Azure sandbox", "error", err)
// 	}

// 	poolClient := azure.InitPoolClient(
// 		projectTagPrefix+"test",
// 		azurePoolId,
// 		sb.Provider.azurePoolApiSecret,
// 	)

// 	err = poolClient.ReleasePool()
// 	if err != nil {
// 		log.Logger.Error("Error releasing Azure sandbox", "error", err)
// 	}

// 	_, err = sb.Provider.DbPool.Exec(
// 		context.Background(),
// 		`DELETE FROM resources WHERE id = $1`,
// 		sb.Id,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to remove resource: %w", err)
// 	}

// 	return nil
// }

// ////////////////////// MOCKUPS ////////////////////////
// TODO: this mockup code shoul be deleted
func (sb *AzureSandboxWithCreds) Create() {
	err := sb.allocatePool()
	if err != nil {
		log.Logger.Error("Can't allocate pool for new Azure Sandbox", "error", err)
		sb.setStatus("error")
		return
	}

	// This is a just mockup, normally it should be filled
	// by the code whichi really create sandbox
	sandboxInfo := azure.SandboxInfo{
		SubscriptionName:  sb.SubscriptionName,
		SubscriptionId:    "test-subscription-id",
		ResourceGroupName: "test-resource-group-name",
		AppID:             "test-app-id",
		DisplayName:       "test-display-name",
		Password:          "test-password",
	}

	// Summary
	fmt.Printf("\n\n"+
		"Sandbox Info:\n"+
		"\tSubscription Name: %s\n"+
		"\tSubscription ID: %s\n"+
		"\tResource Group Name: %s\n"+
		"\tApp ID: %s\n"+
		"\tDisplay Name: %s\n"+
		"\tPassword: %s\n\n",
		sandboxInfo.SubscriptionName,
		sandboxInfo.SubscriptionId,
		sandboxInfo.ResourceGroupName,
		sandboxInfo.AppID,
		sandboxInfo.DisplayName,
		sandboxInfo.Password,
	)

	sb.SubscriptionId = sandboxInfo.SubscriptionId
	sb.ResourceGroupName = sandboxInfo.ResourceGroupName
	sb.AppID = sandboxInfo.AppID
	sb.DisplayName = sandboxInfo.DisplayName
	sb.Credentials = []any{
		map[string]string{
			"password": sandboxInfo.Password,
		},
	}

	sb.Status = "success"
	err = sb.Save()
	if err != nil {
		log.Logger.Error("Can't update Azure Sandbox status", "error", err)
		return
	}
}

// models.Deletable interface implementation
func (sb *AzureSandboxWithCreds) Delete() error {
	fmt.Printf("\n\nSandbox: %s (%d) for deletion!\n\n", sb.Name, sb.Id)

	// TODO: Implement cleanup here
	// Sandbox cleanup can take time, so probably we should run it asynchronously
	// at least yielding control and check for delete process complete periodically
	// if it possible via API

	_, err := sb.Provider.DbPool.Exec(
		context.Background(),
		`DELETE FROM resources WHERE id = $1`,
		sb.Id,
	)
	if err != nil {
		return fmt.Errorf("failed to remove resource: %w", err)
	}

	return nil
}

//////////////////////// MOCKUPS ////////////////////////

// - Create simple "pool" function that return random poolID between pool-01-001 - pool-01-010
// - Create mockups function that will return BS date to store at the database.
//   The important part here is to get poolID from the the "pool" function created above.
// - Update the "pool" function to get existed pools from the database.
// - Update the "pool" function to return only free pools
// - Update the "pool" function to make it single treaded. This probably will require some global
//   items like locks or workgroups.

// We have two places that we need to block:
// - allocate pool and save it to the database
// - release pool and remove it from the database

// My thoughts are:

// Create two functions
// - AllocatePool. Get pointer to sandbox structure as parameter, check for "free"
//   sandbox in the database, assign it or return error and save sandbox info to database.
// - ReleasePool. Also getting sandbox structure as a parameter, set sandbox as nil and
//   save it to database.

// Get list of subscription names from the database with: select resource_data ->> 'subscription_name' as subscription_name from resources;
// poolSize := 10

// for i := 1; i <= poolSize; i++ {
// 	fmt.Printf("%03d\n", i)
//}
