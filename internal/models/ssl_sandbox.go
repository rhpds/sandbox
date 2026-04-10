package models

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
)

type SSLSandboxProvider struct {
	DbPool      *pgxpool.Pool `json:"-"`
	VaultSecret string        `json:"-"`
}

type SSLAccountConfiguration struct {
	ID                  int               `json:"id"`
	Name                string            `json:"name"`
	Domain              string            `json:"domain"`
	MainProvider        string            `json:"main_provider"`
	MainProviderURL     string            `json:"main_provider_url"`
	FallbackProvider    string            `json:"fallback_provider,omitempty"`
	FallbackProviderURL string            `json:"fallback_provider_url,omitempty"`
	Endpoint            string            `json:"endpoint"`
	Token               string            `json:"token,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
	Annotations         map[string]string `json:"annotations"`
	Valid               bool              `json:"valid"`
	AdditionalVars      map[string]any    `json:"additional_vars,omitempty"`
	DbPool              *pgxpool.Pool     `json:"-"`
	VaultSecret         string            `json:"-"`
}

type SSLAccountConfigurations []SSLAccountConfiguration

type SSLSandbox struct {
	Account
	Name                         string            `json:"name"`
	Kind                         string            `json:"kind"`
	ServiceUuid                  string            `json:"service_uuid"`
	SSLAccountConfigurationName  string            `json:"ssl_account"`
	Annotations                  map[string]string `json:"annotations"`
	Status                       string            `json:"status"`
	ErrorMessage                 string            `json:"error_message,omitempty"`
	CleanupCount                 int               `json:"cleanup_count"`
	AdditionalVars               map[string]any    `json:"additional_vars,omitempty"`
	ToCleanup                    bool              `json:"to_cleanup"`
}

type SSLSandboxWithCreds struct {
	SSLSandbox
	Credentials []any              `json:"credentials,omitempty"`
	Provider    *SSLSandboxProvider `json:"-"`
}

type SSLServiceAccount struct {
	Kind                string `json:"kind"`
	KID                 string `json:"kid"`
	Secret              string `json:"secret"`
	Domain              string `json:"domain"`
	Gateway             string `json:"gateway"`
	MainProvider        string `json:"main_provider"`
	MainProviderURL     string `json:"main_provider_url"`
	FallbackProvider    string `json:"fallback_provider,omitempty"`
	FallbackProviderURL string `json:"fallback_provider_url,omitempty"`
}

type SSLSandboxes []SSLSandbox

var SSLErrNoSchedule = errors.New("No SSL account configuration found")

func MakeSSLAccountConfiguration() *SSLAccountConfiguration {
	p := &SSLAccountConfiguration{}
	p.Valid = true
	return p
}

func NewSSLSandboxProvider(dbpool *pgxpool.Pool, vaultSecret string) SSLSandboxProvider {
	return SSLSandboxProvider{
		DbPool:      dbpool,
		VaultSecret: vaultSecret,
	}
}

// --- Bind / Render -----------------------------------------------------------

func (p *SSLAccountConfiguration) Bind(r *http.Request) error {
	if p.Name == "" {
		return errors.New("name is required")
	}
	if !DNSnameRegex.MatchString(p.Name) {
		return errors.New("name is invalid, must be only alphanumeric and '-'")
	}
	if p.Domain == "" {
		return errors.New("domain is required")
	}
	if p.MainProvider == "" {
		return errors.New("main_provider is required")
	}
	if p.MainProviderURL == "" {
		return errors.New("main_provider_url is required")
	}
	if p.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	if p.Token == "" {
		return errors.New("token is required")
	}
	if len(p.Annotations) == 0 {
		return errors.New("annotations is required")
	}
	return nil
}

func (p *SSLAccountConfiguration) Render(w http.ResponseWriter, r *http.Request) error  { return nil }
func (p *SSLAccountConfigurations) Render(w http.ResponseWriter, r *http.Request) error { return nil }
func (a *SSLSandbox) Render(w http.ResponseWriter, r *http.Request) error               { return nil }
func (a *SSLSandboxWithCreds) Render(w http.ResponseWriter, r *http.Request) error      { return nil }

// --- Account Configuration CRUD ---------------------------------------------

func (p *SSLAccountConfiguration) Save() error {
	if p.ID != 0 {
		return p.Update()
	}
	if err := p.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO ssl_account_configurations
			(name, domain, main_provider, main_provider_url,
			 fallback_provider, fallback_provider_url,
			 endpoint, token,
			 annotations, valid, additional_vars)
			VALUES ($1, $2, $3, $4, $5, $6, $7,
				pgp_sym_encrypt($8::text, $9),
				$10, $11, $12)
			RETURNING id`,
		p.Name, p.Domain,
		p.MainProvider, p.MainProviderURL,
		p.FallbackProvider, p.FallbackProviderURL,
		p.Endpoint, p.Token, p.VaultSecret,
		p.Annotations, p.Valid, p.AdditionalVars,
	).Scan(&p.ID); err != nil {
		return err
	}
	return nil
}

func (p *SSLAccountConfiguration) Update() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}
	if _, err := p.DbPool.Exec(
		context.Background(),
		`UPDATE ssl_account_configurations
		 SET name = $1,
			 domain = $2,
			 main_provider = $3,
			 main_provider_url = $4,
			 fallback_provider = $5,
			 fallback_provider_url = $6,
			 endpoint = $7,
			 token = pgp_sym_encrypt($8::text, $9),
			 annotations = $10,
			 valid = $11,
			 additional_vars = $12
		 WHERE id = $13`,
		p.Name, p.Domain,
		p.MainProvider, p.MainProviderURL,
		p.FallbackProvider, p.FallbackProviderURL,
		p.Endpoint, p.Token, p.VaultSecret,
		p.Annotations, p.Valid, p.AdditionalVars,
		p.ID,
	); err != nil {
		return err
	}
	return nil
}

func (p *SSLAccountConfiguration) Delete() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}
	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM ssl_account_configurations WHERE id = $1",
		p.ID,
	)
	return err
}

func (p *SSLAccountConfiguration) Disable() error {
	p.Valid = false
	return p.Update()
}

func (p *SSLAccountConfiguration) Enable() error {
	p.Valid = true
	return p.Update()
}

func (p *SSLAccountConfiguration) GetAccountCount() (int, error) {
	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources WHERE resource_type = 'SSLSandbox' AND resource_data->>'ssl_account' = $1",
		p.Name,
	).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// --- Provider queries --------------------------------------------------------

func (p *SSLSandboxProvider) GetSSLAccountConfigurationByName(name string) (SSLAccountConfiguration, error) {
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT id, name, domain,
			main_provider, main_provider_url,
			COALESCE(fallback_provider, ''), COALESCE(fallback_provider_url, ''),
			endpoint, pgp_sym_decrypt(token, $1),
			created_at, updated_at, annotations, valid, additional_vars
		 FROM ssl_account_configurations WHERE name = $2`,
		p.VaultSecret, name,
	)
	var account SSLAccountConfiguration
	if err := row.Scan(
		&account.ID, &account.Name, &account.Domain,
		&account.MainProvider, &account.MainProviderURL,
		&account.FallbackProvider, &account.FallbackProviderURL,
		&account.Endpoint, &account.Token,
		&account.CreatedAt, &account.UpdatedAt,
		&account.Annotations, &account.Valid, &account.AdditionalVars,
	); err != nil {
		return SSLAccountConfiguration{}, err
	}
	account.DbPool = p.DbPool
	account.VaultSecret = p.VaultSecret
	return account, nil
}

func (p *SSLSandboxProvider) GetSSLAccountConfigurations() (SSLAccountConfigurations, error) {
	accounts := []SSLAccountConfiguration{}
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT id, name, domain,
			main_provider, main_provider_url,
			COALESCE(fallback_provider, ''), COALESCE(fallback_provider_url, ''),
			endpoint, pgp_sym_decrypt(token, $1),
			created_at, updated_at, annotations, valid, additional_vars
		 FROM ssl_account_configurations`,
		p.VaultSecret,
	)
	if err != nil {
		return accounts, err
	}
	for rows.Next() {
		var account SSLAccountConfiguration
		if err := rows.Scan(
			&account.ID, &account.Name, &account.Domain,
			&account.MainProvider, &account.MainProviderURL,
			&account.FallbackProvider, &account.FallbackProviderURL,
			&account.Endpoint, &account.Token,
			&account.CreatedAt, &account.UpdatedAt,
			&account.Annotations, &account.Valid, &account.AdditionalVars,
		); err != nil {
			return nil, err
		}
		account.DbPool = p.DbPool
		account.VaultSecret = p.VaultSecret
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (p *SSLSandboxProvider) GetSchedulableAccounts(cloud_selector map[string]string) (SSLAccountConfigurations, error) {
	accounts := SSLAccountConfigurations{}
	query, args := BuildSchedulableQuery("ssl_account_configurations", cloud_selector, nil, nil)
	rows, err := p.DbPool.Query(context.Background(), query, args...)
	if err != nil {
		log.Logger.Error("Error querying ssl accounts", "error", err)
		return nil, err
	}
	for rows.Next() {
		var accountName string
		if err := rows.Scan(&accountName); err != nil {
			return nil, err
		}
		account, err := p.GetSSLAccountConfigurationByName(accountName)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// --- Resource CRUD -----------------------------------------------------------

func (a *SSLSandboxWithCreds) Save() error {
	if a.ID != 0 {
		return a.Update()
	}
	creds, _ := json.Marshal(a.Credentials)
	withoutCreds := *a
	withoutCreds.Credentials = []any{}
	if err := a.Provider.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO resources
			(resource_name, resource_type, service_uuid, to_cleanup, resource_data, resource_credentials, status, cleanup_count)
			VALUES ($1, $2, $3, $4, $5, pgp_sym_encrypt($6::text, $7), $8, $9) RETURNING id, created_at, updated_at`,
		a.Name, a.Kind, a.ServiceUuid, a.ToCleanup, withoutCreds, creds, a.Provider.VaultSecret, a.Status, a.CleanupCount,
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return err
	}
	return nil
}

func (a *SSLSandboxWithCreds) Update() error {
	if a.ID == 0 {
		return errors.New("id must be > 0")
	}
	creds, _ := json.Marshal(a.Credentials)
	withoutCreds := *a
	withoutCreds.Credentials = []any{}
	if _, err := a.Provider.DbPool.Exec(
		context.Background(),
		`UPDATE resources
		 SET resource_name = $1, resource_type = $2, service_uuid = $3,
			 resource_data = $4, resource_credentials = pgp_sym_encrypt($5::text, $6),
			 status = $7, cleanup_count = $8
		 WHERE id = $9`,
		a.Name, a.Kind, a.ServiceUuid, withoutCreds, creds, a.Provider.VaultSecret,
		a.Status, a.CleanupCount, a.ID,
	); err != nil {
		return err
	}
	return nil
}

func (a *SSLSandboxWithCreds) SetStatus(status string) error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		fmt.Sprintf(`UPDATE resources
		 SET status = $1, resource_data['status'] = to_jsonb('%s'::text)
		 WHERE id = $2`, status),
		status, a.ID,
	)
	return err
}

func (a *SSLSandboxWithCreds) GetStatus() (string, error) {
	var status string
	err := a.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1",
		a.ID,
	).Scan(&status)
	return status, err
}

func (a *SSLSandboxWithCreds) MarkForCleanup() error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' WHERE id = $1",
		a.ID,
	)
	return err
}

func (a *SSLSandboxWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET cleanup_count = cleanup_count + 1 WHERE id = $1",
		a.ID,
	)
	return err
}

// --- Fetch -------------------------------------------------------------------

func (a *SSLSandboxProvider) FetchAllByServiceUuid(serviceUuid string) ([]SSLSandbox, error) {
	accounts := []SSLSandbox{}
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT r.resource_data, r.id, r.resource_name, r.resource_type,
			r.created_at, r.updated_at, r.status, r.cleanup_count,
			COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		FROM resources r
		LEFT JOIN ssl_account_configurations oc ON oc.name = r.resource_data->>'ssl_account'
		WHERE r.service_uuid = $1 AND r.resource_type = 'SSLSandbox'
		ORDER BY r.id`,
		serviceUuid,
	)
	if err != nil {
		return accounts, err
	}
	for rows.Next() {
		var account SSLSandbox
		if err := rows.Scan(
			&account, &account.ID, &account.Name, &account.Kind,
			&account.CreatedAt, &account.UpdatedAt, &account.Status,
			&account.CleanupCount, &account.AdditionalVars,
		); err != nil {
			return accounts, err
		}
		account.ServiceUuid = serviceUuid
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (a *SSLSandboxProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]SSLSandboxWithCreds, error) {
	sandboxes := []SSLSandboxWithCreds{}
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT r.resource_data, r.id, r.resource_name, r.resource_type,
			r.created_at, r.updated_at, r.status, r.cleanup_count,
			pgp_sym_decrypt(r.resource_credentials, $2),
			COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		FROM resources r
		LEFT JOIN ssl_account_configurations oc ON oc.name = r.resource_data->>'ssl_account'
		WHERE r.service_uuid = $1 AND r.resource_type = 'SSLSandbox'
		ORDER BY r.id`,
		serviceUuid, a.VaultSecret,
	)
	if err != nil {
		return sandboxes, err
	}
	for rows.Next() {
		var sandbox SSLSandboxWithCreds
		creds := ""
		if err := rows.Scan(
			&sandbox, &sandbox.ID, &sandbox.Name, &sandbox.Kind,
			&sandbox.CreatedAt, &sandbox.UpdatedAt, &sandbox.Status,
			&sandbox.CleanupCount, &creds, &sandbox.AdditionalVars,
		); err != nil {
			return sandboxes, err
		}
		if err := json.Unmarshal([]byte(creds), &sandbox.Credentials); err != nil {
			return sandboxes, err
		}
		sandbox.ServiceUuid = serviceUuid
		sandbox.Provider = a
		sandboxes = append(sandboxes, sandbox)
	}
	return sandboxes, nil
}

func (a *SSLSandboxProvider) FetchAll() ([]SSLSandbox, error) {
	sandboxes := []SSLSandbox{}
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT r.resource_data, r.id, r.resource_name, r.resource_type,
			r.created_at, r.updated_at, r.status, r.cleanup_count,
			COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		 FROM resources r
		 LEFT JOIN ssl_account_configurations oc ON oc.name = r.resource_data->>'ssl_account' AND r.resource_type = 'SSLSandbox'`,
	)
	if err != nil {
		return sandboxes, err
	}
	for rows.Next() {
		var sandbox SSLSandbox
		if err := rows.Scan(
			&sandbox, &sandbox.ID, &sandbox.Name, &sandbox.Kind,
			&sandbox.CreatedAt, &sandbox.UpdatedAt, &sandbox.Status,
			&sandbox.CleanupCount, &sandbox.AdditionalVars,
		); err != nil {
			return sandboxes, err
		}
		sandboxes = append(sandboxes, sandbox)
	}
	return sandboxes, nil
}

func (p *SSLSandboxProvider) FetchByName(name string) (SSLSandbox, error) {
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT r.resource_data, r.id, r.resource_name, r.resource_type,
			r.created_at, r.updated_at, r.status, r.cleanup_count,
			COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		 FROM resources r
		 LEFT JOIN ssl_account_configurations oc ON oc.name = resource_data->>'ssl_account'
		 WHERE r.resource_name = $1 AND r.resource_type = 'SSLSandbox'`,
		name,
	)
	var sandbox SSLSandbox
	if err := row.Scan(
		&sandbox, &sandbox.ID, &sandbox.Name, &sandbox.Kind,
		&sandbox.CreatedAt, &sandbox.UpdatedAt, &sandbox.Status,
		&sandbox.CleanupCount, &sandbox.AdditionalVars,
	); err != nil {
		return SSLSandbox{}, err
	}
	return sandbox, nil
}

func (p *SSLSandboxProvider) FetchById(id int) (SSLSandbox, error) {
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT r.resource_data, r.id, r.resource_name, r.resource_type,
			r.created_at, r.updated_at, r.status, r.cleanup_count,
			COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		 FROM resources r
		 LEFT JOIN ssl_account_configurations oc ON oc.name = resource_data->>'ssl_account'
		 WHERE r.id = $1 AND r.resource_type = 'SSLSandbox'`,
		id,
	)
	var sandbox SSLSandbox
	if err := row.Scan(
		&sandbox, &sandbox.ID, &sandbox.Name, &sandbox.Kind,
		&sandbox.CreatedAt, &sandbox.UpdatedAt, &sandbox.Status,
		&sandbox.CleanupCount, &sandbox.AdditionalVars,
	); err != nil {
		return SSLSandbox{}, err
	}
	return sandbox, nil
}

func (a *SSLSandboxWithCreds) Reload() error {
	if a.ID == 0 {
		return errors.New("id must be > 0 to use Reload()")
	}
	if a.Provider == nil {
		return errors.New("provider must be set to use Reload()")
	}
	row := a.Provider.DbPool.QueryRow(
		context.Background(),
		`SELECT r.resource_data, r.id, r.resource_name, r.resource_type,
			r.created_at, r.updated_at, r.status, r.cleanup_count,
			pgp_sym_decrypt(r.resource_credentials, $2),
			COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		 FROM resources r
		 LEFT JOIN ssl_account_configurations oc ON oc.name = resource_data->>'ssl_account'
		 WHERE r.id = $1 AND r.resource_type = 'SSLSandbox'`,
		a.ID, a.Provider.VaultSecret,
	)
	var creds string
	var sandbox SSLSandboxWithCreds
	if err := row.Scan(
		&sandbox, &sandbox.ID, &sandbox.Name, &sandbox.Kind,
		&sandbox.CreatedAt, &sandbox.UpdatedAt, &sandbox.Status,
		&sandbox.CleanupCount, &creds, &sandbox.AdditionalVars,
	); err != nil {
		return err
	}
	sandbox.Provider = a.Provider
	*a = sandbox
	if err := json.Unmarshal([]byte(creds), &a.Credentials); err != nil {
		return err
	}
	return nil
}

// --- Gateway-ACME HTTP client ------------------------------------------------

func acmeCreateCredential(endpoint, token, kid string) (secret string, err error) {
	body, _ := json.Marshal(map[string]string{"kid": kid})
	req, err := http.NewRequest("POST", strings.TrimRight(endpoint, "/")+"/admin/credentials", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("acme gateway request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("acme gateway returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		KID    string `json:"kid"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("acme gateway response decode error: %w", err)
	}
	return result.Secret, nil
}

func acmeDeleteCredential(endpoint, token, kid string) error {
	req, err := http.NewRequest("DELETE", strings.TrimRight(endpoint, "/")+"/admin/credentials/"+url.PathEscape(kid), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("acme gateway request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("acme gateway returned status %d: %s", resp.StatusCode, string(respBody))
}

// --- Request / Release / Delete ----------------------------------------------

func (a *SSLSandboxProvider) Request(serviceUuid string, cloud_selector map[string]string, annotations map[string]string, ctx context.Context) (SSLSandboxWithCreds, error) {
	if _, exists := annotations["guid"]; !exists {
		return SSLSandboxWithCreds{}, errors.New("guid not found in annotations")
	}

	candidateAccounts, err := a.GetSchedulableAccounts(cloud_selector)
	if err != nil {
		log.Logger.Error("Error getting schedulable SSL accounts", "error", err)
		return SSLSandboxWithCreds{}, err
	}
	if len(candidateAccounts) == 0 {
		log.Logger.Error("No SSL account configuration found", "cloud_selector", cloud_selector)
		return SSLSandboxWithCreds{}, SSLErrNoSchedule
	}

	selectedAccount := candidateAccounts[0]
	guid := annotations["guid"]
	kid := guid

	rnew := SSLSandboxWithCreds{
		SSLSandbox: SSLSandbox{
			Name:        kid,
			Kind:        "SSLSandbox",
			Annotations: annotations,
			ServiceUuid: serviceUuid,
			Status:      "initializing",
		},
		Provider: a,
	}
	rnew.SSLAccountConfigurationName = selectedAccount.Name
	rnew.Resource.CreatedAt = time.Now()
	rnew.Resource.UpdatedAt = time.Now()

	secret, err := acmeCreateCredential(selectedAccount.Endpoint, selectedAccount.Token, kid)
	if err != nil {
		log.Logger.Error("Error creating SSL credential", "error", err, "kid", kid)
		return SSLSandboxWithCreds{}, err
	}

	rnew.Credentials = []any{
		SSLServiceAccount{
			Kind:                "SSL",
			KID:                 kid,
			Secret:              secret,
			Domain:              selectedAccount.Domain,
			Gateway:             selectedAccount.Endpoint,
			MainProvider:        selectedAccount.MainProvider,
			MainProviderURL:     selectedAccount.MainProviderURL,
			FallbackProvider:    selectedAccount.FallbackProvider,
			FallbackProviderURL: selectedAccount.FallbackProviderURL,
		},
	}
	rnew.Status = "success"

	if err := rnew.Save(); err != nil {
		log.Logger.Error("Error saving SSL account, cleaning up credential", "error", err)
		_ = acmeDeleteCredential(selectedAccount.Endpoint, selectedAccount.Token, kid)
		return SSLSandboxWithCreds{}, err
	}

	return rnew, nil
}

func (a *SSLSandboxProvider) Release(service_uuid string) error {
	sandboxes, err := a.FetchAllByServiceUuidWithCreds(service_uuid)
	if err != nil {
		return err
	}

	var errorHappened error
	for _, sandbox := range sandboxes {
		if sandbox.SSLAccountConfigurationName == "" &&
			sandbox.Status != "error" &&
			sandbox.Status != "scheduling" &&
			sandbox.Status != "initializing" {
			errorHappened = errors.New("SSLAccountConfigurationName not found for sandbox")
			log.Logger.Error("SSLAccountConfigurationName not found for sandbox", "sandbox", sandbox)
			continue
		}
		if err := sandbox.Delete(); err != nil {
			errorHappened = err
			continue
		}
	}
	return errorHappened
}

func (sandbox *SSLSandbox) Delete() error {
	sandboxWithCreds := SSLSandboxWithCreds{
		SSLSandbox: *sandbox,
	}
	return sandboxWithCreds.Delete()
}

func (sandbox *SSLSandboxWithCreds) Delete() error {
	if sandbox.ID == 0 {
		return errors.New("resource ID must be > 0")
	}

	maxRetries := 10
	for {
		status, err := sandbox.GetStatus()
		if err != nil {
			if err == pgx.ErrNoRows {
				log.Logger.Info("SSL resource not found", "name", sandbox.Name)
				return nil
			}
			log.Logger.Error("cannot get status of SSL resource", "error", err, "name", sandbox.Name)
			break
		}
		if maxRetries == 0 {
			log.Logger.Error("SSL resource is not in a final state", "name", sandbox.Name, "status", status)
			if status == "initializing" || status == "scheduling" {
				if err := sandbox.SetStatus("error"); err != nil {
					log.Logger.Error("Cannot set status", "error", err)
					return err
				}
				maxRetries = 10
				continue
			}
			return errors.New("SSL resource is not in a final state, cannot delete")
		}
		if status == "success" || status == "error" {
			break
		}
		time.Sleep(5 * time.Second)
		maxRetries--
	}

	if err := sandbox.Reload(); err != nil {
		log.Logger.Error("Error reloading SSL sandbox", "error", err)
		return err
	}

	if sandbox.SSLAccountConfigurationName == "" {
		_, err := sandbox.Provider.DbPool.Exec(
			context.Background(),
			"DELETE FROM resources WHERE id = $1",
			sandbox.ID,
		)
		return err
	}

	sandbox.SetStatus("deleting")
	sandbox.MarkForCleanup()
	sandbox.IncrementCleanupCount()

	sslaccount, err := sandbox.Provider.GetSSLAccountConfigurationByName(sandbox.SSLAccountConfigurationName)
	if err != nil {
		log.Logger.Error("Error getting SSL account configuration", "error", err)
		sandbox.SetStatus("error")
		return err
	}

	if len(sandbox.Credentials) > 0 {
		credsSandbox, ok := sandbox.Credentials[0].(map[string]interface{})
		if ok {
			if kid, ok := credsSandbox["kid"].(string); ok && kid != "" {
				if err := acmeDeleteCredential(sslaccount.Endpoint, sslaccount.Token, kid); err != nil {
					log.Logger.Error("Error deleting SSL credential", "error", err, "kid", kid)
					sandbox.SetStatus("error")
					return err
				}
			}
		}
	}

	_, err = sandbox.Provider.DbPool.Exec(
		context.Background(),
		"DELETE FROM resources WHERE id = $1",
		sandbox.ID,
	)
	return err
}
