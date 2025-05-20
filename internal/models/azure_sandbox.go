package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	//	"sync"
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
	DbPool        *pgxpool.Pool `json:"-"`
	VaultSecret   string        `json:"-"`

	//poolMutex sync.Mutex
}

type AzureAccountConfiguration struct {
	ID                     int               `json:"id"`
	Name                   string            `json:"name"`
	ClientID               string            `json:"client_id"`
	TenantID               string            `json:"tenant_id"`
	Secret                 string            `json:"secret"`
	SubscriptionNamePrefix string            `json:"sub_name_prefix,omitempty"`
	SubscriptionRangeStart int               `json:"sub_range_start,omitempty"`
	SubscriptionRangeEnd   int               `json:"sub_range_end,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
	Annotations            map[string]string `json:"annotations"`
	Valid                  bool              `json:"valid"`
	AdditionalVars         map[string]any    `json:"additional_vars,omitempty"`
	DbPool                 *pgxpool.Pool     `json:"-"`
	VaultSecret            string            `json:"-"`
}

type AzureSandboxWithCreds struct {
	AzureSandbox

	Credentials []any                 `json:"credentials"`
	Provider    *AzureSandboxProvider `json:"-"`
}

type AzureSandbox struct {
	Account
	ID                            int            `json:"id,omitempty"`
	Name                          string         `json:"name"`
	Kind                          string         `json:"kind"` // AzureSandbox
	ServiceUuid                   string         `json:"service_uuid"`
	AzureAccountConfigurationName string         `json:"azure_account"`
	Annotations                   Annotations    `json:"annotations"`
	Status                        string         `json:"status"`
	CleanupCount                  int            `json:"cleanup_count"`
	AdditionalVars                map[string]any `json:"additional_vars,omitempty"`
	ToCleanup                     bool           `json:"to_cleanup"`
	SubscriptionName              string         `json:"subscription_name"`
	SubscriptionId                string         `json:"subscription_id"`
	ResourceGroupName             string         `json:"resource_group_name"`
	AppID                         string         `json:"app_id"`
	DisplayName                   string         `json:"display_name"`
}

type AzureAccountConfigurations []AzureAccountConfiguration

var AzurenameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// MakeAzureAccountConfiguration creates a new AzureAccountConfiguration
// with default values
func MakeAzureAccountConfiguration() *AzureAccountConfiguration {
	p := &AzureAccountConfiguration{}

	p.Valid = true
	return p
}

func NewAzureSandboxProvider(
	DbPool *pgxpool.Pool,
	VaultSecret string,
) AzureSandboxProvider {
	return AzureSandboxProvider{
		DbPool:      DbPool,
		VaultSecret: VaultSecret,
	}

}

func (a *AzureSandboxProvider) allocateSubscription() (string, error) {
	SubscriptionNames := map[string]bool{}

	// Subscription names are not defined but used to get Subscription ID
	// using Azure API calls. For simplicity we are using the subscriptionCount
	// subscriptions starting from pool-01-001.
	for i := 100; i <= 100+subscriptionCount; i++ {
		SubscriptionNames[fmt.Sprintf("%s%d", subscriptionNamePrefix, i)] = false
	}

	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT resource_data ->> 'subscription_name' FROM resources WHERE status = 'success' and resource_type='AzureSandbox'`,
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
	// agonzalez: TODO
	//a.poolMutex.Lock()
	//defer a.poolMutex.Unlock()

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

var AzureErrNoSchedule error = errors.New("No Azure account configuration found")

func (a *AzureSandboxProvider) GetAzureSchedulableAccounts(cloud_selector map[string]string) (AzureAccountConfigurations, error) {
	accounts := AzureAccountConfigurations{}
	// Get resource from 'azure_account_configurations' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT name FROM azure_account_configurations WHERE annotations @> $1 and valid=true ORDER BY random()`,
		cloud_selector,
	)

	if err != nil {
		log.Logger.Error("Error querying azure accounts", "error", err)
		return AzureAccountConfigurations{}, err
	}

	for rows.Next() {
		var accountName string

		if err := rows.Scan(&accountName); err != nil {
			return AzureAccountConfigurations{}, err
		}

		account, err := a.GetAzureAccountConfigurationByName(accountName)
		if err != nil {
			return AzureAccountConfigurations{}, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (a *AzureSandboxProvider) Request(serviceUuid string, cloud_selector map[string]string, annotations map[string]string, multiple bool, ctx context.Context) (AzureSandboxWithCreds, error) {
	if _, exists := annotations["guid"]; !exists {
		return AzureSandboxWithCreds{}, errors.New("guid not found in annotations")
	}

	// Version with AzureAccountConfiguration methods
	candidateAccounts, err := a.GetAzureSchedulableAccounts(cloud_selector)
	if err != nil {
		log.Logger.Error("Error getting schedulable accounts", "error", err)
		return AzureSandboxWithCreds{}, err
	}
	if len(candidateAccounts) == 0 {
		log.Logger.Error("No Azure account configuration found", "cloud_selector", cloud_selector)
		return AzureSandboxWithCreds{}, AzureErrNoSchedule
	}

	var selectedAccount = candidateAccounts[0]

	// Determine guid, auto increment the guid if there are multiple resources
	// for a serviceUuid
	guid, err := AzureguessNextGuid(annotations["guid"], serviceUuid, a.DbPool, multiple, ctx)
	if err != nil {
		log.Logger.Error("Error guessing guid", "error", err)
		return AzureSandboxWithCreds{}, err
	}

	suffix := annotations["sandbox_suffix"]
	if suffix != "" {
		guid = guid + "-" + suffix
	}

	azureSandbox, err := a.initNewAzureSandbox(serviceUuid, annotations)
	azureSandbox.AzureAccountConfigurationName = selectedAccount.Name
	azureSandbox.Resource.CreatedAt = time.Now()
	azureSandbox.Resource.UpdatedAt = time.Now()
	if err != nil {
		log.Logger.Error("Can't init new Azure sandbox", "error", err)
		return AzureSandboxWithCreds{}, err
	}

	// Create the sandbox asynchronously
	go azureSandbox.Create(selectedAccount)

	return *azureSandbox, nil
}

func (a *AzureSandboxProvider) FetchAllByServiceUuid(serviceUuid string) ([]AzureSandbox, error) {
	sandboxes := []AzureSandbox{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
			resource_data,
			id,
			resource_name,
			resource_type,
			status,
			cleanup_count
		FROM
			resources
		WHERE service_uuid = $1 AND resource_type = 'AzureSandbox'`,
		serviceUuid,
	)
	if err != nil {
		fmt.Printf("\n\nSQL error: %s\n\n", err)
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found", "service_uuid", serviceUuid)
		}
		return sandboxes, err
	}

	for rows.Next() {
		var sandbox AzureSandbox

		if err := rows.Scan(
			&sandbox,
			&sandbox.ID,
			&sandbox.Name,
			&sandbox.Kind,
			&sandbox.Status,
			&sandbox.CleanupCount,
		); err != nil {
			return sandboxes, err
		}

		sandbox.ServiceUuid = serviceUuid

		sandboxes = append(sandboxes, sandbox)
	}

	return sandboxes, nil
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
			&sandbox.ID,
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

func (p *AzureSandboxProvider) FetchByName(name string) (AzureSandbox, error) {
	// Get resource from above 'resources' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 r.resource_data,
		 r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		 FROM resources r
		 LEFT JOIN azure_account_configurations oc ON oc.name = resource_data->>'azure_account'
		 WHERE r.resource_name = $1 and r.resource_type = 'AzureSandbox'`,
		name,
	)

	var sandbox AzureSandbox
	if err := row.Scan(
		&sandbox,
		&sandbox.ID,
		&sandbox.Name,
		&sandbox.Kind,
		&sandbox.CreatedAt,
		&sandbox.UpdatedAt,
		&sandbox.Status,
		&sandbox.CleanupCount,
		&sandbox.AdditionalVars,
	); err != nil {
		return AzureSandbox{}, err
	}
	return sandbox, nil
}

func (a *AzureSandboxProvider) FetchAll() ([]AzureSandbox, error) {
	sandboxes := []AzureSandbox{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
		 r.resource_data,
		 r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		 FROM resources r
		 LEFT JOIN azure_account_configurations oc ON oc.name = r.resource_data->>'azure_account' AND r.resource_type = 'AzureSandbox'`,
	)

	if err != nil {
		return sandboxes, err
	}

	for rows.Next() {
		var sandbox AzureSandbox
		if err := rows.Scan(
			&sandbox,
			&sandbox.ID,
			&sandbox.Name,
			&sandbox.Kind,
			&sandbox.CreatedAt,
			&sandbox.UpdatedAt,
			&sandbox.Status,
			&sandbox.CleanupCount,
			&sandbox.AdditionalVars,
		); err != nil {
			return sandboxes, err
		}

		sandboxes = append(sandboxes, sandbox)
	}

	return sandboxes, nil
}

func AzureguessNextGuid(origGuid string, serviceUuid string, dbpool *pgxpool.Pool, multiple bool, ctx context.Context) (string, error) {
	var rowcount int
	guid := origGuid
	increment := 0

	if multiple {
		guid = origGuid + "-1"
	}

	for {
		if increment > 100 {
			return "", errors.New("Too many iterations guessing guid")
		}

		if increment > 0 {
			guid = origGuid + "-" + fmt.Sprintf("%v", increment+1)
		}
		// If a sandbox already has the same name for that serviceuuid, increment
		// If so, increment the guid and try again
		candidateName := guid

		err := dbpool.QueryRow(
			context.Background(),
			`SELECT count(*) FROM resources
			WHERE resource_name = $1
			AND resource_type = 'AzureSandbox'`,
			candidateName,
		).Scan(&rowcount)

		if err != nil {
			return "", err
		}

		if rowcount == 0 {
			break
		}
		increment++
	}

	return guid, nil
}

func (a *AzureSandboxProvider) Release(serviceUuid string) error {
	sandboxes, err := a.FetchAllByServiceUuidWithCreds(serviceUuid)
	if err != nil {
		return err
	}
	var errorHappened error

	for _, sandbox := range sandboxes {
		if sandbox.AzureAccountConfigurationName == "" &&
			sandbox.Status != "error" &&
			sandbox.Status != "scheduling" &&
			sandbox.Status != "initializing" {
			// If the sandbox is not in error and the namespace is empty, throw an error
			errorHappened = errors.New("DNSAccountConfigurationName not found for sandbox")
			log.Logger.Error("DNSAccountConfigurationName not found for sandbox", "sandbox", sandbox)
			continue
		}
		sandbox.Provider = a
		if err := sandbox.Delete(); err != nil {
			errorHappened = err
			continue
		}
	}
	return errorHappened
}

func (sb *AzureSandboxWithCreds) Update() error {
	if sb.ID == 0 {
		return fmt.Errorf("failed to update resources, ID is not set")
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
		sb.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update resource: %w", err)
	}

	return nil
}

// Bind and Render
func (p *AzureAccountConfiguration) Bind(r *http.Request) error {
	// Ensure the name is not empty
	if p.Name == "" {
		return errors.New("name is required")
	}

	// Ensure the name is valid
	if !AzurenameRegex.MatchString(p.Name) {
		return errors.New("name is invalid, must be only alphanumeric and '-'")
	}

	// Ensure ClientID is not empty
	if p.ClientID == "" {
		return errors.New("client_id is required")
	}

	// Ensure TenantID is not empty
	if p.TenantID == "" {
		return errors.New("TenantID is required")
	}

	// Ensure Secret is not empty
	if p.Secret == "" {
		return errors.New("Secret must be defined")
	}

	if len(p.Annotations) == 0 {
		return errors.New("annotations is required")
	}
	return nil
}

func (p *AzureAccountConfiguration) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// Bind and Render for AzureAccountConfigurations
func (p *AzureAccountConfigurations) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *AzureAccountConfiguration) Save() error {
	if p.ID != 0 {
		return p.Update()
	}

	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources",
		p.Name,
	).Scan(&count); err != nil {
		log.Logger.Info(fmt.Sprintf("%d", count))
	}

	// Insert resource and get Id
	if err := p.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO azure_account_configurations
      (name,
      tenant_id,
      client_id,
      secret,
      sub_name_prefix,
      sub_range_start,
      sub_range_end,
      annotations,
      valid,
      additional_vars)
      VALUES ($1, $2, $3, pgp_sym_encrypt($4::text, $5), $6, $7, $8, $9, $10, $11)
      RETURNING id`,
		p.Name,
		p.TenantID,
		p.ClientID,
		p.Secret,
		p.VaultSecret,
		p.SubscriptionNamePrefix,
		p.SubscriptionRangeStart,
		p.SubscriptionRangeEnd,
		p.Annotations,
		p.Valid,
		p.AdditionalVars,
	).Scan(&p.ID); err != nil {
		return err
	}
	return nil
}

func (p *AzureAccountConfiguration) Update() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	// Update resource
	if _, err := p.DbPool.Exec(
		context.Background(),
		`UPDATE azure_account_configurations
		 SET name = $1,
			 tenant_id = $2,
			 client_id = $3,
			 secret = pgp_sym_encrypt($4::text, $5),
			 annotations = $6,
			 valid = $7,
			 additional_vars = $8,
			 sub_name_prefix = $9,
			 sub_range_start = $10,
			 sub_range_end = $11 
		 WHERE id = $12`,
		p.Name,
		p.TenantID,
		p.ClientID,
		p.Secret,
		p.VaultSecret,
		p.Annotations,
		p.Valid,
		p.AdditionalVars,
		p.SubscriptionNamePrefix,
		p.SubscriptionRangeStart,
		p.SubscriptionRangeEnd,
		p.ID,
	); err != nil {
		return err
	}
	return nil
}

func (p *AzureAccountConfiguration) Delete() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM azure_account_configurations WHERE id = $1",
		p.ID,
	)
	return err
}

// Disable an AzureAccountConfiguration
func (p *AzureAccountConfiguration) Disable() error {
	p.Valid = false
	return p.Update()
}

// Enable an AzureAccountConfiguration
func (p *AzureAccountConfiguration) Enable() error {
	p.Valid = true
	return p.Update()
}

// CountAccounts returns the number of accounts for an AzureAccountConfiguration
func (p *AzureAccountConfiguration) GetAccountCount() (int, error) {
	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources WHERE resource_type = 'AzureSandbox' AND resource_data->>'azure_account' = $1",
		p.Name,
	).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// GetAzureAccountConfigurationByName returns an AzureAccountConfiguration by name
func (p *AzureSandboxProvider) GetAzureAccountConfigurationByName(name string) (AzureAccountConfiguration, error) {
	// Get resource from above 'azure_account_configurations' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
			id,
			name,
			client_id,
			tenant_id,
			pgp_sym_decrypt(secret::bytea, $1),
			sub_name_prefix,
			sub_range_start,
			sub_range_end,
			created_at,
			updated_at,
			annotations,
			valid,
			additional_vars
		 FROM azure_account_configurations WHERE name = $2`,
		p.VaultSecret, name,
	)

	var account AzureAccountConfiguration
	if err := row.Scan(
		&account.ID,
		&account.Name,
		&account.ClientID,
		&account.TenantID,
		&account.Secret,
		&account.SubscriptionNamePrefix,
		&account.SubscriptionRangeStart,
		&account.SubscriptionRangeEnd,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Annotations,
		&account.Valid,
		&account.AdditionalVars,
	); err != nil {
		return AzureAccountConfiguration{}, err
	}
	account.DbPool = p.DbPool
	account.VaultSecret = p.VaultSecret
	return account, nil
}

// GetAzureAccountConfigurations returns the full list of AzureAccountConfiguration
func (p *AzureSandboxProvider) GetAzureAccountConfigurations() (AzureAccountConfigurations, error) {
	accounts := []AzureAccountConfiguration{}

	// Get resource from 'azure_account_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT
			id,
			name,
			client_id,
			tenant_id,
			pgp_sym_decrypt(secret::bytea, $1),
			sub_name_prefix,
			sub_range_start,
			sub_range_end,
			created_at,
			updated_at,
			annotations,
			valid,
			additional_vars
		 FROM azure_account_configurations`,
		p.VaultSecret,
	)

	if err != nil {
		return []AzureAccountConfiguration{}, err
	}

	for rows.Next() {
		var account AzureAccountConfiguration

		if err := rows.Scan(
			&account.ID,
			&account.Name,
			&account.ClientID,
			&account.TenantID,
			&account.Secret,
			&account.SubscriptionNamePrefix,
			&account.SubscriptionRangeStart,
			&account.SubscriptionRangeEnd,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Annotations,
			&account.Valid,
			&account.AdditionalVars,
		); err != nil {
			return []AzureAccountConfiguration{}, err
		}

		account.DbPool = p.DbPool
		account.VaultSecret = p.VaultSecret
		accounts = append(accounts, account)
	}

	return accounts, nil
}

// GetAzureAccountConfigurationByAnnotations returns a list of AzureAccountConfiguration by annotations
func (p *AzureSandboxProvider) GetAzureAccountConfigurationByAnnotations(annotations map[string]string) ([]AzureAccountConfiguration, error) {
	accounts := []AzureAccountConfiguration{}
	// Get resource from above 'azure_account_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT name FROM azure_account_configurations WHERE annotations @> $1`,
		annotations,
	)

	if err != nil {
		return []AzureAccountConfiguration{}, err
	}

	for rows.Next() {
		var accountName string

		if err := rows.Scan(&accountName); err != nil {
			return []AzureAccountConfiguration{}, err
		}

		account, err := p.GetAzureAccountConfigurationByName(accountName)
		if err != nil {
			return []AzureAccountConfiguration{}, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

var AzureErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

func (a *AzureSandbox) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *AzureSandboxWithCreds) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (sb *AzureSandboxWithCreds) Save() error {
	if sb.ID != 0 {
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
	).Scan(&sb.ID)
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
		status, sb.ID,
	)

	return err
}

func (sb *AzureSandboxWithCreds) getStatus() (string, error) {
	var status string
	err := sb.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1",
		sb.ID,
	).Scan(&status)

	return status, err
}

func (sb *AzureSandboxWithCreds) markForCleanup() error {
	_, err := sb.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' where id = $1",
		sb.ID,
	)

	return err
}

func (sb *AzureSandboxWithCreds) Create(account AzureAccountConfiguration) {
	sandboxInfo, err := sb.requestAzureSandbox(account)
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

func (a *AzureSandboxWithCreds) SetStatus(status string) error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		fmt.Sprintf(`UPDATE resources
		 SET status = $1,
			 resource_data['status'] = to_jsonb('%s'::text)
		 WHERE id = $2`, status),
		status, a.ID,
	)

	return err
}

func (a *AzureSandboxWithCreds) GetStatus() (string, error) {
	var status string
	err := a.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1",
		a.ID,
	).Scan(&status)

	return status, err
}

func (a *AzureSandboxWithCreds) MarkForCleanup() error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' WHERE id = $1",
		a.ID,
	)

	return err
}

func (a *AzureSandboxWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET cleanup_count = cleanup_count + 1 WHERE id = $1",
		a.ID,
	)

	return err
}

// models.Deletable interface implementation
func (sandbox *AzureSandboxWithCreds) Delete() error {
	retryCount := deleteMaxRetries
	for {
		if retryCount == 0 {
			err := fmt.Errorf("timeout error")
			log.Logger.Error("can't delete resource", "error", err)
			return err
		}

		sandboxStatus, err := sandbox.getStatus()
		if err != nil {
			log.Logger.Error("can't get status of resource", "error", err, "name", sandbox.Name)
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

	if sandbox.AzureAccountConfigurationName == "" {
		// Get the Azure sandbox configuration name from the resources.resource_data column using ID
		err := sandbox.Provider.DbPool.QueryRow(
			context.Background(),
			"SELECT resource_data->>'azure_sandbox' FROM resources WHERE id = $1",
			sandbox.ID,
		).Scan(&sandbox.AzureAccountConfigurationName)

		if err != nil {
			if err == pgx.ErrNoRows {
				log.Logger.Error("Azure sandbox doesn't exist for resource", "name", sandbox.Name)
				sandbox.SetStatus("error")
				return errors.New("Azure sandbox doesn't exist for resource")
			}

			log.Logger.Error("Azure sandbox query error", "err", err)
			sandbox.SetStatus("error")
			return err
		}
	}

	if sandbox.AzureAccountConfigurationName == "" {
		// The resource was not created, nothing to delete
		// that happens when no sandbox is elected
		_, err := sandbox.Provider.DbPool.Exec(
			context.Background(),
			"DELETE FROM resources WHERE id = $1",
			sandbox.ID,
		)
		return err
	}


	sandbox.setStatus("deleting")
	sandbox.markForCleanup()

	azureaccount, err := sandbox.Provider.GetAzureAccountConfigurationByName(sandbox.AzureAccountConfigurationName)
	if err != nil {
		log.Logger.Error("Error getting Azure account configuration", "error", err)
		sandbox.SetStatus("error")
		return err
	}

	err = sandbox.cleanupAzureSandbox(azureaccount)
	if err != nil {
		log.Logger.Error("can't delete Azure resources", "error", err, "name", sandbox.Name)
		sandbox.setStatus("error")
		return err
	}

	_, err = sandbox.Provider.DbPool.Exec(
		context.Background(),
		`DELETE FROM resources WHERE id = $1`,
		sandbox.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove resource: %w", err)
	}

	return nil
}

func (sb *AzureSandboxWithCreds) requestAzureSandbox(account AzureAccountConfiguration) (*azure.SandboxInfo, error) {
	sandboxClient := azure.InitSandboxClient(
		azure.AzureCredentials{
				TenantID: account.TenantID,
				ClientID: account.ClientID,
			  Secret:   account.Secret,
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

func (sb *AzureSandboxWithCreds) cleanupAzureSandbox(account AzureAccountConfiguration) error {
	sandboxClient := azure.InitSandboxClient(
		azure.AzureCredentials{
				TenantID: account.TenantID,
				ClientID: account.ClientID,
			  Secret:   account.Secret,
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
