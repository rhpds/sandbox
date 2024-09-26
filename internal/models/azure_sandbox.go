package models

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/api/azure"
	"github.com/rhpds/sandbox/internal/log"
)

const (
	subscriptionNamePrefix = "pool-01-"
	subscriptionCount      = 10

	// Sand box can be in state when deletion is not possible
	// (e.g initializating). Those two constants controls
	// how long delay process will last until error occurs
	// up to deleteMaxRetries * deleteRetryDelay seconds
	deleteMaxRetries = 10
	deleteRetryDelay = 5
)

type AzureSandboxProvider struct {
	dbPool      *pgxpool.Pool
	vaultSecret string

	azureTenantId      string
	azureClientId      string
	azureSecret        string
	azurePoolApiSecret string

	poolMutex sync.Mutex
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
) (*AzureSandboxProvider, error) {
	provider := &AzureSandboxProvider{
		dbPool:      dbPool,
		vaultSecret: vaultSecret,
	}

	if provider.azureTenantId = os.Getenv("AZURE_TENANT_ID"); provider.azureTenantId == "" {
		return nil, fmt.Errorf("AZURE_TENANT_ID is not set")
	}

	if provider.azureClientId = os.Getenv("AZURE_CLIENT_ID"); provider.azureClientId == "" {
		return nil, fmt.Errorf("AZURE_CLIENT_ID is not set")
	}

	if provider.azureSecret = os.Getenv("AZURE_SECRET"); provider.azureSecret == "" {
		return nil, fmt.Errorf("AZURE_SECRET is not set")
	}

	if provider.azurePoolApiSecret = os.Getenv("AZURE_POOL_API_SECRET"); provider.azurePoolApiSecret == "" {
		return nil, fmt.Errorf("AZURE_POOL_API_SECRET is not set")
	}

	return provider, nil
}

func (a *AzureSandboxProvider) allocateSubscription() (string, error) {
	SubscriptionNames := map[string]bool{}

	// Subscription names are not defined but used to get Subscription ID
	// using Azure API calls. For simplicity we are using the subscriptionCount
	// subscriptions starting from pool-01-001.
	for i := 1; i <= subscriptionCount; i++ {
		SubscriptionNames[fmt.Sprintf("%s%d", subscriptionNamePrefix, i)] = false
	}

	rows, err := a.dbPool.Query(
		context.Background(),
		`SELECT resource_data ->> 'subscription_name' FROM resources WHERE status = 'success'`,
	)
	if err != nil {
		return "", fmt.Errorf("can't get retrieve about allocated pools")
	}
	defer rows.Close()

	allocatedSubscriptions := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return "", fmt.Errorf("illegal pool name retrieved: %w", err)
		}
		allocatedSubscriptions = append(allocatedSubscriptions, name)
	}
	if err = rows.Err(); err != nil {
		return "", fmt.Errorf("can't get allocated pool names: %w", err)
	}

	for _, name := range allocatedSubscriptions {
		if _, exists := SubscriptionNames[name]; exists {
			SubscriptionNames[name] = true
		} else {
			log.Logger.Warn("Incorrect pool name found", "warning", name)
			continue
		}
	}

	availableSubscriptions := make([]string, 0, len(SubscriptionNames))
	for k, v := range SubscriptionNames {
		if !v {
			availableSubscriptions = append(availableSubscriptions, k)
		}
	}

	if len(availableSubscriptions) == 0 {
		return "", fmt.Errorf("no available pools")
	}

	return availableSubscriptions[rand.Intn(len(availableSubscriptions))], nil
}

func (a *AzureSandboxProvider) getNewSandboxName(guid string, serviceUuid string) (string, error) {
	if guid == "" || serviceUuid == "" {
		return "", fmt.Errorf("guid or serviceUuid is invalid")
	}

	return fmt.Sprintf("%s-1-%s", guid, serviceUuid), nil
}

func (a *AzureSandboxProvider) initNewAzureSandbox(serviceUuid string, annotations Annotations) (*AzureSandboxWithCreds, error) {
	// Multiple Azure sandboxes can be initialize concurently
	// and we should be sure that we are getting correct values
	// for the new AzureSandboxWithCreds structure
	a.poolMutex.Lock()
	defer a.poolMutex.Unlock()

	azureSandbox := AzureSandboxWithCreds{
		AzureSandbox: AzureSandbox{
			Name:        "noname",
			Kind:        "AzureSandbox",
			ServiceUuid: serviceUuid,
			Annotations: annotations,
			Status:      "initializing",
		},
		Provider: a,
	}

	sandboxName, err := a.getNewSandboxName(
		annotations["guid"],
		serviceUuid,
	)
	if err != nil {
		return nil, err
	}
	azureSandbox.AzureSandbox.Name = sandboxName

	subscriptionName, err := a.allocateSubscription()
	if err != nil {
		return nil, err
	}

	azureSandbox.SubscriptionName = subscriptionName

	err = azureSandbox.Save()
	if err != nil {
		return nil, err
	}

	return &azureSandbox, nil
}

func (a *AzureSandboxProvider) Request(
	serviceUuid string,
	annotations Annotations,
) (AzureSandboxWithCreds, error) {
	azureSandbox, err := a.initNewAzureSandbox(serviceUuid, annotations)
	if err != nil {
		log.Logger.Error("Can't init new Azure sandbox", "error", err)
		return AzureSandboxWithCreds{}, err
	}

	// Create the sandbox asynchronously
	go azureSandbox.Create()

	return *azureSandbox, nil
}

func (a *AzureSandboxProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]AzureSandboxWithCreds, error) {
	sandboxes := []AzureSandboxWithCreds{}
	// Get resource from above 'resources' table
	rows, err := a.dbPool.Query(
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
		serviceUuid, a.vaultSecret,
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

	_, err = sb.Provider.dbPool.Exec(
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
		sb.Provider.vaultSecret,
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

	err = sb.Provider.dbPool.QueryRow(
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
		sb.Provider.vaultSecret,
		sb.Status,
		sb.CleanupCount,
	).Scan(&sb.Id)
	if err != nil {
		return fmt.Errorf("failed to insert resource: %w", err)
	}

	return nil
}

func (sb *AzureSandboxWithCreds) setStatus(status string) error {
	_, err := sb.Provider.dbPool.Exec(
		context.Background(),
		fmt.Sprintf(`UPDATE resources
			SET status = $1,
			resource_data['status'] = to_jsonb('%s'::text)
			WHERE id = $2`, status),
		status, sb.Id,
	)

	return err
}

func (sb *AzureSandboxWithCreds) getStatus() (string, error) {
	var status string
	err := sb.Provider.dbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1",
		sb.Id,
	).Scan(&status)

	return status, err
}

func (sb *AzureSandboxWithCreds) markForCleanup() error {
	_, err := sb.Provider.dbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' where id = $1",
		sb.Id,
	)

	return err
}

func (sb *AzureSandboxWithCreds) Create() {
	sandboxInfo, err := sb.requestAzureSandbox()
	if err == nil {
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
	} else {
		log.Logger.Error("can't create Azure sandbox", "error", err, "name", sb.Name)
		sb.Status = "error"
	}

	err = sb.Save()
	if err != nil {
		log.Logger.Error("can't update Azure Sandbox status", "error", err)
		return
	}
}

// models.Deletable interface implementation
func (sb *AzureSandboxWithCreds) Delete() error {
	retryCount := deleteMaxRetries
	for {
		if retryCount == 0 {
			err := fmt.Errorf("timeout error")
			log.Logger.Error("can't delete resource", "error", err)
			return err
		}

		sandboxStatus, err := sb.getStatus()
		if err != nil {
			log.Logger.Error("can't get status of resource", "error", err, "name", sb.Name)
			return err
		}

		if sandboxStatus == "deleting" {
			return nil
		}

		if sandboxStatus == "success" || sandboxStatus == "error" {
			break
		}

		time.Sleep(deleteRetryDelay * time.Second)
		retryCount--
	}

	sb.setStatus("deleting")
	sb.markForCleanup()

	err := sb.cleanupAzureSandbox()
	if err != nil {
		log.Logger.Error("can't delete Azure resources", "error", err, "name", sb.Name)
		sb.setStatus("error")
		return err
	}

	_, err = sb.Provider.dbPool.Exec(
		context.Background(),
		`DELETE FROM resources WHERE id = $1`,
		sb.Id,
	)
	if err != nil {
		return fmt.Errorf("failed to remove resource: %w", err)
	}

	return nil
}

func (sb *AzureSandboxWithCreds) requestAzureSandbox() (*azure.SandboxInfo, error) {
	sandboxClient := azure.InitSandboxClient(
		azure.AzureCredentials{
			TenantID: sb.Provider.azureTenantId,
			ClientID: sb.Provider.azureClientId,
			Secret:   sb.Provider.azureSecret,
		},
	)

	sandboxInfo, err := sandboxClient.CreateSandboxEnvironment(
		sb.SubscriptionName,
		sb.Annotations["requester"],
		sb.Annotations["guid"],
		sb.Annotations["cost_center"],
		sb.Annotations["domain"],
	)
	if err != nil {
		return nil, err
	}

	return sandboxInfo, nil
}

func (sb *AzureSandboxWithCreds) cleanupAzureSandbox() error {
	sandboxClient := azure.InitSandboxClient(
		azure.AzureCredentials{
			TenantID: sb.Provider.azureTenantId,
			ClientID: sb.Provider.azureClientId,
			Secret:   sb.Provider.azureSecret,
		},
	)

	err := sandboxClient.CleanupSandboxEnvironment(
		sb.SubscriptionName,
		sb.Annotations["guid"],
	)
	if err != nil {
		return err
	}

	return nil
}
