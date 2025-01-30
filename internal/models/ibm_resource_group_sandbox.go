package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
)

type IBMResourceGroupSandboxProvider struct {
	DbPool      *pgxpool.Pool `json:"-"`
	VaultSecret string        `json:"-"`
}

type IBMResourceGroupSandboxConfiguration struct {
	ID             int               `json:"id"`
	Name           string            `json:"name"`
	APIKey         string            `json:"apikey"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Annotations    map[string]string `json:"annotations"`
	Valid          bool              `json:"valid"`
	AdditionalVars map[string]any    `json:"additional_vars,omitempty"`
	DbPool         *pgxpool.Pool     `json:"-"`
	VaultSecret    string            `json:"-"`
}

type IBMResourceGroupSandboxConfigurations []IBMResourceGroupSandboxConfiguration

type IBMResourceGroupSandbox struct {
	Account
	Name                                     string            `json:"name"`
	Kind                                     string            `json:"kind"` // "IBMResourceGroupSandbox"
	ServiceUuid                              string            `json:"service_uuid"`
	IBMResourceGroupSandboxConfigurationName string            `json:"ibm_resource_group_account"`
	Annotations                              map[string]string `json:"annotations"`
	Status                                   string            `json:"status"`
	ErrorMessage                             string            `json:"error_message,omitempty"`
	ResourceGroup                            string            `json:"resourcegroup"`
	CleanupCount                             int               `json:"cleanup_count"`
	DeployerAdditionalVars                   map[string]any    `json:"deployer_additional_vars,omitempty"`
	ToCleanup                                bool              `json:"to_cleanup"`
}

type IBMResourceGroupSandboxWithCreds struct {
	IBMResourceGroupSandbox

	Credentials []any                            `json:"credentials,omitempty"`
	Provider    *IBMResourceGroupSandboxProvider `json:"-"`
}

// Credential for service account
type IBMResourceGroupServiceAccount struct {
	Name   string `json:"name"`
	APIKey string `json:"apikey"`
}

type IBMResourceGroupSandboxes []IBMResourceGroupSandbox

type APIKeyResponse struct {
	AccessAPIKey string `json:"access_apikey"`
}

var IBMResourceGroupSandboxNameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// MakeIBMResourceGroupSandboxConfiguration creates a new IBMResourceGroupSandboxConfiguration
// with default values
func MakeIBMResourceGroupSandboxConfiguration() *IBMResourceGroupSandboxConfiguration {
	p := &IBMResourceGroupSandboxConfiguration{}

	p.Valid = true
	return p
}

// Bind and Render
func (p *IBMResourceGroupSandboxConfiguration) Bind(r *http.Request) error {
	// Ensure the name is not empty
	if p.Name == "" {
		return errors.New("name is required")
	}

	// Ensure the name is valid
	if !IBMResourceGroupSandboxNameRegex.MatchString(p.Name) {
		return errors.New("name is invalid, must be only alphanumeric and '-'")
	}

	// Ensure APIKey is provided
	if len(p.APIKey) == 0 {
		return errors.New("apikey is required")
	}

	// Ensure Annotations is provided
	if len(p.Annotations) == 0 {
		return errors.New("annotations is required")
	}

	return nil
}

func (p *IBMResourceGroupSandboxConfiguration) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// Bind and Render for IBMResourceGroupSandboxConfigurations
func (p *IBMResourceGroupSandboxConfigurations) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *IBMResourceGroupSandboxConfiguration) Save() error {
	if p.ID != 0 {
		return p.Update()
	}

	// Insert resource and get Id
	if err := p.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO ibm_resource_group_account_configurations
			(name,
			apikey,
			annotations,
			valid,
			additional_vars)
			VALUES ($1, pgp_sym_encrypt($3::text, $2),$4, $5, $6)
			RETURNING id`,
		p.Name,
		p.VaultSecret,
		p.APIKey,
		p.Annotations,
		p.Valid,
		p.AdditionalVars,
	).Scan(&p.ID); err != nil {
		return err
	}
	return nil
}

func (p *IBMResourceGroupSandboxConfiguration) Update() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	// Update resource
	if _, err := p.DbPool.Exec(
		context.Background(),
		`UPDATE ibm_resource_group_account_configurations
		 SET name = $1,
			 apikey = pgp_sym_encrypt($3::text, $2),
			 annotations = $4,
			 valid = $5,
			 additional_vars = $6
		 WHERE id = $7`,
		p.Name,
		p.VaultSecret,
		p.APIKey,
		p.Annotations,
		p.Valid,
		p.AdditionalVars,
		p.ID,
	); err != nil {
		return err
	}
	return nil
}

func (p *IBMResourceGroupSandboxConfiguration) Delete() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM ibm_resource_group_account_configurations WHERE id = $1",
		p.ID,
	)
	return err
}

// Disable an IBMResourceGroupSandboxConfiguration
func (p *IBMResourceGroupSandboxConfiguration) Disable() error {
	p.Valid = false
	return p.Update()
}

// Enable an IBMResourceGroupSandboxConfiguration
func (p *IBMResourceGroupSandboxConfiguration) Enable() error {
	p.Valid = true
	return p.Update()
}

// CountAccounts returns the number of accounts for an IBMResourceGroupSandboxConfiguration
func (p *IBMResourceGroupSandboxConfiguration) GetAccountCount() (int, error) {
	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources WHERE resource_type = 'IBMResourceGroupSandbox' AND resource_data->>'ibm_resource_group_account' = $1",
		p.Name,
	).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// GetIBMResourceGroupSandboxConfigurationByName returns an IBMResourceGroupSandboxConfiguration by name
func (p *IBMResourceGroupSandboxProvider) GetIBMResourceGroupSandboxConfigurationByName(name string) (IBMResourceGroupSandboxConfiguration, error) {
	// Get resource from above 'ibm_resource_group_account_configurations' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
			id,
			name,
			pgp_sym_decrypt(apikey::bytea, $1),
			created_at,
			updated_at,
			annotations,
			valid,
			additional_vars
		 FROM ibm_resource_group_account_configurations WHERE name = $2`,
		p.VaultSecret, name,
	)

	var cluster IBMResourceGroupSandboxConfiguration
	if err := row.Scan(
		&cluster.ID,
		&cluster.Name,
		&cluster.APIKey,
		&cluster.CreatedAt,
		&cluster.UpdatedAt,
		&cluster.Annotations,
		&cluster.Valid,
		&cluster.AdditionalVars,
	); err != nil {
		return IBMResourceGroupSandboxConfiguration{}, err
	}
	cluster.DbPool = p.DbPool
	cluster.VaultSecret = p.VaultSecret
	return cluster, nil
}

// GetIBMResourceGroupSandboxConfigurations returns the full list of IBMResourceGroupSandboxConfiguration
func (p *IBMResourceGroupSandboxProvider) GetIBMResourceGroupSandboxConfigurations() (IBMResourceGroupSandboxConfigurations, error) {
	clusters := []IBMResourceGroupSandboxConfiguration{}

	// Get resource from 'ibm_resource_group_account_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT
			id,
			name,
			pgp_sym_decrypt(apikey::bytea, $1),
			created_at,
			updated_at,
			annotations,
			valid,
			additional_vars
		 FROM ibm_resource_group_account_configurations`,
		p.VaultSecret,
	)

	if err != nil {
		return []IBMResourceGroupSandboxConfiguration{}, err
	}

	for rows.Next() {
		var cluster IBMResourceGroupSandboxConfiguration

		if err := rows.Scan(
			&cluster.ID,
			&cluster.Name,
			&cluster.APIKey,
			&cluster.CreatedAt,
			&cluster.UpdatedAt,
			&cluster.Annotations,
			&cluster.Valid,
			&cluster.AdditionalVars,
		); err != nil {
			return []IBMResourceGroupSandboxConfiguration{}, err
		}

		cluster.DbPool = p.DbPool
		cluster.VaultSecret = p.VaultSecret
		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

// GetIBMResourceGroupSandboxConfigurationByAnnotations returns a list of IBMResourceGroupSandboxConfiguration by annotations
func (p *IBMResourceGroupSandboxProvider) GetIBMResourceGroupSandboxConfigurationByAnnotations(annotations map[string]string) ([]IBMResourceGroupSandboxConfiguration, error) {
	clusters := []IBMResourceGroupSandboxConfiguration{}
	// Get resource from above 'ibm_resource_group_account_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT name FROM ibm_resource_group_account_configurations WHERE annotations @> $1`,
		annotations,
	)

	if err != nil {
		return []IBMResourceGroupSandboxConfiguration{}, err
	}

	for rows.Next() {
		var clusterName string

		if err := rows.Scan(&clusterName); err != nil {
			return []IBMResourceGroupSandboxConfiguration{}, err
		}

		cluster, err := p.GetIBMResourceGroupSandboxConfigurationByName(clusterName)
		if err != nil {
			return []IBMResourceGroupSandboxConfiguration{}, err
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

var IBMErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

func (a *IBMResourceGroupSandbox) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *IBMResourceGroupSandboxWithCreds) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *IBMResourceGroupSandbox) Save(dbpool *pgxpool.Pool) error {
	// Check if resource already exists in the DB
	if err := dbpool.QueryRow(
		context.Background(),
		`INSERT INTO resources
		 (resource_name, resource_type, service_uuid, resource_data, status, cleanup_count)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		a.Name, a.Kind, a.ServiceUuid, a, a.Status, a.CleanupCount).Scan(&a.ID); err != nil {
		return err
	}

	return nil
}

func (a *IBMResourceGroupSandboxWithCreds) Update() error {

	if a.ID == 0 {
		return errors.New("id must be > 0")
	}

	creds, _ := json.Marshal(a.Credentials)
	withoutCreds := *a
	withoutCreds.Credentials = []any{}

	// Update resource
	if _, err := a.Provider.DbPool.Exec(
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
		a.Name,
		a.Kind,
		a.ServiceUuid,
		withoutCreds,
		creds,
		a.Provider.VaultSecret,
		a.Status,
		a.CleanupCount,
		a.ID,
	); err != nil {
		return err
	}
	return nil
}

func (a *IBMResourceGroupSandboxWithCreds) Save() error {
	if a.ID != 0 {
		return a.Update()
	}
	creds, _ := json.Marshal(a.Credentials)
	// Unset credentials in a struct withoutCreds
	withoutCreds := *a
	withoutCreds.Credentials = []any{}
	// Insert resource and get Id
	if err := a.Provider.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO resources
			(resource_name, resource_type, service_uuid, to_cleanup, resource_data, resource_credentials, status, cleanup_count)
			VALUES ($1, $2, $3, $4, $5, pgp_sym_encrypt($6::text, $7), $8, $9) RETURNING id`,
		a.Name, a.Kind, a.ServiceUuid, a.ToCleanup, withoutCreds, creds, a.Provider.VaultSecret, a.Status, a.CleanupCount,
	).Scan(&a.ID); err != nil {
		return err
	}

	return nil
}

func (a *IBMResourceGroupSandboxWithCreds) SetStatus(status string) error {
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

func (a *IBMResourceGroupSandboxWithCreds) GetStatus() (string, error) {
	var status string
	err := a.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1",
		a.ID,
	).Scan(&status)

	return status, err
}

func (a *IBMResourceGroupSandboxWithCreds) MarkForCleanup() error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' WHERE id = $1",
		a.ID,
	)

	return err
}

func (a *IBMResourceGroupSandboxWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET cleanup_count = cleanup_count + 1 WHERE id = $1",
		a.ID,
	)

	return err
}
func (a *IBMResourceGroupSandboxProvider) FetchAllByServiceUuid(serviceUuid string) ([]IBMResourceGroupSandbox, error) {
	accounts := []IBMResourceGroupSandbox{}
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
			COALESCE(oc.additional_vars, '{}'::jsonb) AS account_additional_vars
		FROM
			resources r
		LEFT JOIN
			ibm_resource_group_account_configurations oc ON oc.name = r.resource_data->>'ibm_resource_group_account'
		WHERE r.service_uuid = $1 AND r.resource_type = 'IBMResourceGroupSandbox'`,
		serviceUuid,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account IBMResourceGroupSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.DeployerAdditionalVars,
		); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (a *IBMResourceGroupSandboxProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]IBMResourceGroupSandboxWithCreds, error) {
	accounts := []IBMResourceGroupSandboxWithCreds{}
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
			pgp_sym_decrypt(r.resource_credentials, $2),
			COALESCE(oc.additional_vars, '{}'::jsonb) AS account_additional_vars
		FROM
			resources r
		LEFT JOIN
			ibm_resource_group_account_configurations oc ON oc.name = r.resource_data->>'ibm_resource_group_account'
		WHERE r.service_uuid = $1 AND r.resource_type = 'IBMResourceGroupSandbox'`,
		serviceUuid, a.VaultSecret,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account IBMResourceGroupSandboxWithCreds

		creds := ""
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&creds,
			&account.DeployerAdditionalVars,
		); err != nil {
			return accounts, err
		}
		// Unmarshal creds into account.Credentials
		if err := json.Unmarshal([]byte(creds), &account.Credentials); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		account.Provider = a

		accounts = append(accounts, account)
	}

	return accounts, nil
}

var IBMErrNoSchedule error = errors.New("No IBM resource group account configuration found")

func (a *IBMResourceGroupSandboxProvider) GetSchedulableAccounts(cloud_selector map[string]string) (IBMResourceGroupSandboxConfigurations, error) {
	clusters := IBMResourceGroupSandboxConfigurations{}
	// Get resource from 'ibm_resource_group_account_configurations' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT name FROM ibm_resource_group_account_configurations WHERE annotations @> $1 and valid=true ORDER BY random()`,
		cloud_selector,
	)

	if err != nil {
		log.Logger.Error("Error querying IBM resource group accounts", "error", err)
		return IBMResourceGroupSandboxConfigurations{}, err
	}

	for rows.Next() {
		var clusterName string

		if err := rows.Scan(&clusterName); err != nil {
			return IBMResourceGroupSandboxConfigurations{}, err
		}

		cluster, err := a.GetIBMResourceGroupSandboxConfigurationByName(clusterName)
		if err != nil {
			return IBMResourceGroupSandboxConfigurations{}, err
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

func (a *IBMResourceGroupSandboxProvider) Request(serviceUuid string, cloud_selector map[string]string, annotations map[string]string, ctx context.Context) (IBMResourceGroupSandboxWithCreds, error) {
	// Ensure annotation has guid
	if _, exists := annotations["guid"]; !exists {
		return IBMResourceGroupSandboxWithCreds{}, errors.New("guid not found in annotations")
	}

	// Version with IBMResourceGroupSandboxConfiguration methods
	candidateAccounts, err := a.GetSchedulableAccounts(cloud_selector)
	if err != nil {
		log.Logger.Error("Error getting IBM resource group accounts", "error", err)
		return IBMResourceGroupSandboxWithCreds{}, err
	}
	if len(candidateAccounts) == 0 {
		log.Logger.Error("No IBM resource group account configuration found", "cloud_selector", cloud_selector)
		return IBMResourceGroupSandboxWithCreds{}, IBMErrNoSchedule
	}

	if len(candidateAccounts) > 1 {
		log.Logger.Error("More than one IBM resource group account configuration found", "cloud_selector", cloud_selector)
		return IBMResourceGroupSandboxWithCreds{}, IBMErrNoSchedule
	}

	// Determine guid, auto increment the guid if there are multiple resources
	// for a serviceUuid
	guid, err := IBMResourceGroupSandboxGuessNextGuid(annotations["guid"], serviceUuid, a.DbPool, ctx)
	if err != nil {
		log.Logger.Error("Error guessing guid", "error", err)
		return IBMResourceGroupSandboxWithCreds{}, err
	}
	// Return the Placement with a status 'initializing'
	rnew := IBMResourceGroupSandboxWithCreds{
		IBMResourceGroupSandbox: IBMResourceGroupSandbox{
			Name:        guid + "-" + serviceUuid,
			Kind:        "IBMResourceGroupSandbox",
			Annotations: annotations,
			ServiceUuid: serviceUuid,
			Status:      "initializing",
		},
		Provider: a,
	}

	rnew.Resource.CreatedAt = time.Now()
	rnew.Resource.UpdatedAt = time.Now()

	if err := rnew.Save(); err != nil {
		log.Logger.Error("Error saving IBM resource group account", "error", err)
		return IBMResourceGroupSandboxWithCreds{}, err
	}

	//--------------------------------------------------
	// The following is async
	go func() {
		selectedAccount := candidateAccounts[0]
		rnew.SetStatus("scheduling")
		log.Logger.Info("Account", "name", selectedAccount.Name)

		rnew.IBMResourceGroupSandboxConfigurationName = selectedAccount.Name

		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving IBM resource group account", "error", err)
			rnew.SetStatus("error")
			return
		}

		suffix := annotations["resourcegroup_suffix"]
		if suffix == "" {
			suffix = serviceUuid
		}

		resourceGroupName := "rg-" + guid + "-" + suffix
		resourceGroupName = resourceGroupName[:min(40, len(resourceGroupName))] // truncate to 40

		authenticator, err := core.NewIamAuthenticatorBuilder().
			SetApiKey(selectedAccount.APIKey).
			Build()

		iamIdentityServiceOptions := &iamidentityv1.IamIdentityV1Options{Authenticator: authenticator}
		iamIdentityService, err := iamidentityv1.NewIamIdentityV1UsingExternalConfig(iamIdentityServiceOptions)
		iamOptions := iamIdentityService.NewGetAPIKeysDetailsOptions()
		iamOptions.SetIamAPIKey(selectedAccount.APIKey)
		userdetails, _, err := iamIdentityService.GetAPIKeysDetails(iamOptions)
		accountID := userdetails.AccountID
		createServiceIDOptions := iamIdentityService.NewCreateServiceIDOptions(*userdetails.AccountID, resourceGroupName)
		serviceID, response, err := iamIdentityService.CreateServiceID(createServiceIDOptions)
		iamID := *serviceID.IamID
		createAPIKeyOptions := iamIdentityService.NewCreateAPIKeyOptions("sandbox", *serviceID.IamID)
		createAPIKeyOptions.SetDescription("Created by sandbox-api")
		apiKey, response, err := iamIdentityService.CreateAPIKey(createAPIKeyOptions)
		apiKeyValue := *apiKey.Apikey

		resourceManagerClientOptions := &resourcemanagerv2.ResourceManagerV2Options{Authenticator: authenticator}
		resourceManagerClient, err := resourcemanagerv2.NewResourceManagerV2UsingExternalConfig(resourceManagerClientOptions)
		resourceGroupCreate := resourcemanagerv2.CreateResourceGroupOptions{
			Name: &resourceGroupName,
		}

		resCreateResourceGroup, response, err := resourceManagerClient.CreateResourceGroup(&resourceGroupCreate)
		if err != nil {
			log.Logger.Error("Error creating Resource Group", "error", err)
			rnew.SetStatus("error")
			return
		}
		resourceGroupId := resCreateResourceGroup.ID
		rnew.ResourceGroup = resourceGroupName
		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving IBM resource group account", "error", err)
			rnew.SetStatus("error")
			return
		}

		iamPolicyManagementServiceOptions := &iampolicymanagementv1.IamPolicyManagementV1Options{Authenticator: authenticator}
		iamPolicyManagementService, err := iampolicymanagementv1.NewIamPolicyManagementV1UsingExternalConfig(iamPolicyManagementServiceOptions)

		// Define policies
		policyAll := &iampolicymanagementv1.CreatePolicyOptions{
			Type: core.StringPtr("access"),
			Roles: []iampolicymanagementv1.PolicyRole{
				{
					RoleID: core.StringPtr("crn:v1:bluemix:public:iam::::serviceRole:Reader"),
				},
				{
					RoleID: core.StringPtr("crn:v1:bluemix:public:iam::::role:Administrator"),
				},
			},
			Resources: []iampolicymanagementv1.PolicyResource{
				{
					Attributes: []iampolicymanagementv1.ResourceAttribute{
						{
							Name:     core.StringPtr("accountId"),
							Value:    accountID,
							Operator: core.StringPtr("stringEquals"),
						},
						{
							Name:     core.StringPtr("resourceGroupId"),
							Value:    resourceGroupId,
							Operator: core.StringPtr("stringEquals"),
						},
					},
				},
			},
			Subjects: []iampolicymanagementv1.PolicySubject{
				{
					Attributes: []iampolicymanagementv1.SubjectAttribute{
						{
							Name:  core.StringPtr("iam_id"),
							Value: &iamID,
						},
					},
				},
			},
		}

		policyRG := &iampolicymanagementv1.CreatePolicyOptions{
			Type: core.StringPtr("access"),
			Roles: []iampolicymanagementv1.PolicyRole{
				{
					RoleID: core.StringPtr("crn:v1:bluemix:public:iam::::role:Viewer"),
				},
			},
			Resources: []iampolicymanagementv1.PolicyResource{
				{
					Attributes: []iampolicymanagementv1.ResourceAttribute{
						{
							Name:     core.StringPtr("accountId"),
							Value:    accountID,
							Operator: core.StringPtr("stringEquals"),
						},
						{
							Name:     core.StringPtr("resourceType"),
							Value:    core.StringPtr("resource-group"),
							Operator: core.StringPtr("stringEquals"),
						},
						{
							Name:     core.StringPtr("resource"),
							Value:    resourceGroupId,
							Operator: core.StringPtr("stringEquals"),
						},
					},
				},
			},
			Subjects: []iampolicymanagementv1.PolicySubject{
				{
					Attributes: []iampolicymanagementv1.SubjectAttribute{
						{
							Name:  core.StringPtr("iam_id"),
							Value: &iamID,
						},
					},
				},
			},
		}

		result, response, err := iamPolicyManagementService.CreatePolicy(policyAll)
		if err != nil {
			log.Logger.Error("Failed to create policy: %v\nResponse: %v", err, response)
			rnew.SetStatus("error")
			return
		}

		log.Logger.Info("IBM policy created correctly", "ID", *result.ID)

		result, response, err = iamPolicyManagementService.CreatePolicy(policyRG)
		if err != nil {
			log.Logger.Error("Failed to create policy: %v\nResponse: %v", err, response)
			rnew.SetStatus("error")
			return
		}

		log.Logger.Info("IBM policy created correctly", "ID", *result.ID)

		creds := []any{
			IBMResourceGroupServiceAccount{
				Name:   resourceGroupName,
				APIKey: apiKeyValue,
			},
		}
		rnew.Credentials = creds
		rnew.Status = "success"

		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving IBM resource group account", "error", err)
			log.Logger.Info("Trying to cleanup IBM resource group account")
			if err := rnew.Delete(); err != nil {
				log.Logger.Error("Error cleaning up IBM resource group account", "error", err)
			}
		}
		log.Logger.Info("IBM sandbox booked", "account", rnew.Name, "service_uuid", rnew.ServiceUuid,
			"cluster", rnew.IBMResourceGroupSandboxConfigurationName, "resourcegroup", rnew.ResourceGroup)
	}()
	//--------------------------------------------------

	return rnew, nil
}

func IBMResourceGroupSandboxGuessNextGuid(origGuid string, serviceUuid string, dbpool *pgxpool.Pool, ctx context.Context) (string, error) {
	var rowcount int
	guid := origGuid
	increment := 0

	for {
		if increment > 100 {
			return "", errors.New("Too many iterations guessing guid")
		}

		if increment > 0 {
			guid = origGuid + "-" + fmt.Sprintf("%v", increment+1)
		}
		// If a sandbox already has the same name for that serviceuuid, increment
		// If so, increment the guid and try again
		candidateName := guid + "-" + serviceUuid

		err := dbpool.QueryRow(
			context.Background(),
			`SELECT count(*) FROM resources
			WHERE resource_name = $1
			AND resource_type = 'IBMResourceGroupSandbox'`,
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

func (a *IBMResourceGroupSandboxProvider) Release(service_uuid string) error {
	accounts, err := a.FetchAllByServiceUuidWithCreds(service_uuid)

	if err != nil {
		return err
	}

	var errorHappened error

	for _, account := range accounts {
		if account.ResourceGroup == "" &&
			account.Status != "error" &&
			account.Status != "scheduling" &&
			account.Status != "initializing" {
			// If the sandbox is not in error and the resourcegroup is empty, throw an error
			errorHappened = errors.New("ResourceGroup not found for account")
			log.Logger.Error("ResourceGroup not found for account", "account", account)
			continue
		}

		if err := account.Delete(); err != nil {
			errorHappened = err
			continue
		}
	}
	return errorHappened
}

func NewIBMResourceGroupSandboxProvider(dbpool *pgxpool.Pool, vaultSecret string) IBMResourceGroupSandboxProvider {
	return IBMResourceGroupSandboxProvider{
		DbPool:      dbpool,
		VaultSecret: vaultSecret,
	}
}

func (a *IBMResourceGroupSandboxProvider) FetchAll() ([]IBMResourceGroupSandbox, error) {
	accounts := []IBMResourceGroupSandbox{}
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
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS account_additional_vars
		 FROM resources r
		 LEFT JOIN ibm_resource_group_account_configurations oc ON oc.name = r.resource_data->>'ibm_resource_group_account' 
		 WHERE r.resource_type = 'IBMResourceGroupSandbox'`,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account IBMResourceGroupSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.DeployerAdditionalVars,
		); err != nil {
			return accounts, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (account *IBMResourceGroupSandboxWithCreds) Delete() error {

	if account.ID == 0 {
		return errors.New("resource ID must be > 0")
	}

	// Wait for the status of the resource until it's in final state
	maxRetries := 10
	for {
		status, err := account.GetStatus()
		if err != nil {
			// if norow, the resource was not created, nothing to delete
			if err == pgx.ErrNoRows {
				log.Logger.Info("Resource not found", "name", account.Name)
				return nil
			}
			log.Logger.Error("cannot get status of resource", "error", err, "name", account.Name)
			break
		}
		if maxRetries == 0 {
			log.Logger.Error("Resource is not in a final state", "name", account.Name, "status", status)

			// Curative and auto-healing action, set status to error
			if status == "initializing" || status == "scheduling" {
				if err := account.SetStatus("error"); err != nil {
					log.Logger.Error("Cannot set status", "error", err)
					return err
				}
				maxRetries = 10
				continue
			}
			return errors.New("Resource is not in a final state, cannot delete")
		}

		if status == "success" || status == "error" {
			break
		}

		time.Sleep(5 * time.Second)
		maxRetries--
	}

	// Reload account
	if err := account.Reload(); err != nil {
		log.Logger.Error("Error reloading account", "error", err)
		return err
	}

	if account.IBMResourceGroupSandboxConfigurationName == "" {
		// Get the IBM resource group account configuration name from the resources.resource_data column using ID
		err := account.Provider.DbPool.QueryRow(
			context.Background(),
			"SELECT resource_data->>'ibm_resource_group_account' FROM resources WHERE id = $1",
			account.ID,
		).Scan(&account.IBMResourceGroupSandboxConfigurationName)

		if err != nil {
			if err == pgx.ErrNoRows {
				log.Logger.Error("IBM cluster doesn't exist for resource", "name", account.Name)
				account.SetStatus("error")
				return errors.New("IBM cluster doesn't exist for resource")
			}

			log.Logger.Error("IBM cluster query error", "err", err)
			account.SetStatus("error")
			return err
		}
	}

	if account.IBMResourceGroupSandboxConfigurationName == "" {
		// The resource was not created, nothing to delete
		// that happens when no cluster is elected
		_, err := account.Provider.DbPool.Exec(
			context.Background(),
			"DELETE FROM resources WHERE id = $1",
			account.ID,
		)
		return err
	}

	account.SetStatus("deleting")
	// In case anything goes wrong, we'll know it can safely be deleted
	account.MarkForCleanup()
	account.IncrementCleanupCount()

	if account.ResourceGroup == "" {
		log.Logger.Info("Empty resourcegroup, consider deletion a success", "name", account.Name)
		_, err := account.Provider.DbPool.Exec(
			context.Background(),
			"DELETE FROM resources WHERE id = $1",
			account.ID,
		)
		return err
	}

	// Get the IBM resource group account configuration from the resources.resource_data column

	ibmResourceGroupAccount, err := account.Provider.GetIBMResourceGroupSandboxConfigurationByName(account.IBMResourceGroupSandboxConfigurationName)
	if err != nil {
		log.Logger.Error("Error getting IBM resource group account configuration", "error", err)
		account.SetStatus("error")
		return err
	}
	authenticator, err := core.NewIamAuthenticatorBuilder().
		SetApiKey(ibmResourceGroupAccount.APIKey).
		Build()

	resourceControllerServiceOptions := &resourcecontrollerv2.ResourceControllerV2Options{Authenticator: authenticator}
	resourceControllerService, err := resourcecontrollerv2.NewResourceControllerV2UsingExternalConfig(resourceControllerServiceOptions)

	resourceManagerClientOptions := &resourcemanagerv2.ResourceManagerV2Options{Authenticator: authenticator}
	resourceManagerClient, err := resourcemanagerv2.NewResourceManagerV2UsingExternalConfig(resourceManagerClientOptions)
	resourceGroupOptions := resourcemanagerv2.ListResourceGroupsOptions{
		Name: &account.ResourceGroup,
	}

	resourceGroup, _, err := resourceManagerClient.ListResourceGroups(&resourceGroupOptions)
	if err != nil {
		log.Logger.Error("Error listing IBM resource group", "error", err)
		account.SetStatus("error")
		return err
	}

	if len(resourceGroup.Resources) > 0 {
		maxRetries := 10
		retryCount := 0
		sleepDuration := time.Second * 5

		listResourceInstancesOptions := &resourcecontrollerv2.ListResourceInstancesOptions{
			ResourceGroupID: resourceGroup.Resources[0].ID,
		}
		for {

			pager, err := resourceControllerService.NewResourceInstancesPager(listResourceInstancesOptions)
			if err != nil {
				log.Logger.Error("Error listing IBM instances", "error", err)
				account.SetStatus("error")
				return err
			}

			var allResults []resourcecontrollerv2.ResourceInstance
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				if err != nil {
					log.Logger.Error("Error listing IBM instances", "error", err)
					account.SetStatus("error")
					return err
				}
				allResults = append(allResults, nextPage...)
			}
			if len(allResults) == 0 {
				break
			}
			// Delete all resource instances
			for _, instance := range allResults {
				if instance.ID == nil {
					continue // Skip instances without an ID
				}

				deleteResourceInstanceOptions := &resourcecontrollerv2.DeleteResourceInstanceOptions{
					ID: instance.ID,
				}

				_, err := resourceControllerService.DeleteResourceInstance(deleteResourceInstanceOptions)
				if err != nil {
					log.Logger.Info("Failed to delete resource instance with IDxx %s: %v", *instance.ID, err)
				} else {
					log.Logger.Info("Successfully deleted resource instance with ID %s\n", *instance.ID, "success")
				}
			}
			retryCount++
			if retryCount >= maxRetries {
				log.Logger.Error("Max retries reached, was not possible to delete all resource instances")
				account.SetStatus("error")
				return err
			}

			// Sleep before retrying
			time.Sleep(sleepDuration)
		}
		deleteResourceGroupOptions := resourcemanagerv2.DeleteResourceGroupOptions{
			ID: resourceGroup.Resources[0].ID,
		}

		_, err = resourceManagerClient.DeleteResourceGroup(&deleteResourceGroupOptions)
		if err != nil {
			log.Logger.Error("Error deleting IBM Resource Group", "error", err)
			account.SetStatus("error")
			return err
		}
	}
	iamIdentityServiceOptions := &iamidentityv1.IamIdentityV1Options{Authenticator: authenticator}
	iamIdentityService, err := iamidentityv1.NewIamIdentityV1UsingExternalConfig(iamIdentityServiceOptions)
	iamOptions := iamIdentityService.NewGetAPIKeysDetailsOptions()
	iamOptions.SetIamAPIKey(ibmResourceGroupAccount.APIKey)
	userdetails, _, err := iamIdentityService.GetAPIKeysDetails(iamOptions)
	accountID := userdetails.AccountID

	listServiceIDOptions := &iamidentityv1.ListServiceIdsOptions{AccountID: accountID, Name: &account.Name}
	services, response, err := iamIdentityService.ListServiceIds(listServiceIDOptions)
	if err != nil {
		log.Logger.Error("Error listing IBM Service ID", "error", err, "response", response)
		account.SetStatus("error")
		return err
	}
	if services != nil && len(services.Serviceids) > 0 {
		deleteServiceIDOptions := iamIdentityService.NewDeleteServiceIDOptions(*services.Serviceids[0].ID)
		_, err = iamIdentityService.DeleteServiceID(deleteServiceIDOptions)
		if err != nil {
			log.Logger.Error("Error deleting IBM Service ID", "error", err)
			account.SetStatus("error")
			return err
		}
	}

	log.Logger.Info("ResourceGroup deleted",
		"name", account.Name,
		"resourcegroup", account.ResourceGroup,
		"cluster", account.IBMResourceGroupSandboxConfigurationName,
	)
	_, err = account.Provider.DbPool.Exec(
		context.Background(),
		"DELETE FROM resources WHERE id = $1",
		account.ID,
	)
	return err
}

func (p *IBMResourceGroupSandboxProvider) FetchByName(name string) (IBMResourceGroupSandbox, error) {
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
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS account_additional_vars
		 FROM resources r
		 LEFT JOIN ibm_resource_group_account_configurations oc ON oc.name = resource_data->>'ibm_resource_group_account'
		 WHERE r.resource_name = $1 AND r.resource_type = 'IBMResourceGroupSandbox'`,
		name,
	)

	var account IBMResourceGroupSandbox
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&account.DeployerAdditionalVars,
	); err != nil {
		return IBMResourceGroupSandbox{}, err
	}
	return account, nil
}

func (p *IBMResourceGroupSandboxProvider) FetchById(id int) (IBMResourceGroupSandbox, error) {
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
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS account_additional_vars
		 FROM resources r
		 LEFT JOIN ibm_resource_group_account_configurations oc ON oc.name = resource_data->>'ibm_resource_group_account'
		 WHERE r.id = $1`,
		id,
	)

	var account IBMResourceGroupSandbox
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&account.DeployerAdditionalVars,
	); err != nil {
		return IBMResourceGroupSandbox{}, err
	}
	return account, nil
}

func (a *IBMResourceGroupSandboxWithCreds) Reload() error {
	// Ensude ID is set
	if a.ID == 0 {
		return errors.New("id must be > 0 to use Reload()")
	}

	// Enusre provider is set
	if a.Provider == nil {
		return errors.New("provider must be set to use Reload()")
	}

	// Get resource from above 'resources' table
	row := a.Provider.DbPool.QueryRow(
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
		 pgp_sym_decrypt(r.resource_credentials, $2),
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS account_additional_vars
		 FROM resources r
		 LEFT JOIN ibm_resource_group_account_configurations oc ON oc.name = resource_data->>'ibm_resource_group_account'
		 WHERE r.id = $1  AND r.resource_type = 'IBMResourceGroupSandbox'`,
		a.ID, a.Provider.VaultSecret,
	)

	var creds string
	var account IBMResourceGroupSandboxWithCreds
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&creds,
		&account.DeployerAdditionalVars,
	); err != nil {
		return err
	}
	// Add provider before copying
	account.Provider = a.Provider
	// Copy account into a
	*a = account

	// Unmarshal creds into account.Credentials
	if err := json.Unmarshal([]byte(creds), &a.Credentials); err != nil {
		return err
	}

	return nil
}
