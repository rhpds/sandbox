package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/IBM/go-sdk-core/v5/core"
  "github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
  "github.com/IBM/platform-services-go-sdk/iamidentityv1"
  "github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
  "github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
)

type IBMSharedSandboxProvider struct {
	DbPool      *pgxpool.Pool `json:"-"`
	VaultSecret string        `json:"-"`
}

type IBMSharedSandboxConfiguration struct {
	ID                       int               `json:"id"`
	Name                     string            `json:"name"`
	APIKey                   string            `json:"apikey"`
	CreatedAt                time.Time         `json:"created_at"`
	UpdatedAt                time.Time         `json:"updated_at"`
	Annotations              map[string]string `json:"annotations"`
	Valid                    bool              `json:"valid"`
	AdditionalVars           map[string]any    `json:"additional_vars,omitempty"`
	DbPool                   *pgxpool.Pool     `json:"-"`
	VaultSecret              string            `json:"-"`
}

type IBMSharedSandboxConfigurations []IBMSharedSandboxConfiguration

type IBMSharedSandbox struct {
	Account
	Name                              string            `json:"name"`
	Kind                              string            `json:"kind"` // "IBMSharedSandbox"
	ServiceUuid                       string            `json:"service_uuid"`
	IBMSharedSandboxConfigurationName string            `json:"ibm_shared_account"`
	Annotations                       map[string]string `json:"annotations"`
	Status                            string            `json:"status"`
	ErrorMessage                      string            `json:"error_message,omitempty"`
	ResourceGroup                     string            `json:"resourcegroup"`
	CleanupCount                      int               `json:"cleanup_count"`
	AccountAdditionalVars             map[string]any    `json:"cluster_additional_vars,omitempty"`
	ToCleanup                         bool              `json:"to_cleanup"`
}

type IBMSharedSandboxWithCreds struct {
	IBMSharedSandbox

	Credentials []any               `json:"credentials,omitempty"`
	Provider    *IBMSharedSandboxProvider `json:"-"`
}

// Credential for service account
type IBMSharedServiceAccount struct {
	Name  string `json:"name"`
	APIKey string `json:"apikey"`
}

type IBMSharedSandboxes []IBMSharedSandbox

type APIKeyResponse struct {
	AccessAPIKey string `json:"access_apikey"`
}

var IBMSharedSandboxNameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// MakeIBMSharedSandboxConfiguration creates a new IBMSharedSandboxConfiguration
// with default values
func MakeIBMSharedSandboxConfiguration() *IBMSharedSandboxConfiguration {
	p := &IBMSharedSandboxConfiguration{}

	p.Valid = true
	return p
}

// Bind and Render
func (p *IBMSharedSandboxConfiguration) Bind(r *http.Request) error {
	// Ensure the name is not empty
	if p.Name == "" {
		return errors.New("name is required")
	}

	// Ensure the name is valid
	if !IBMSharedSandboxNameRegex.MatchString(p.Name) {
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

func (p *IBMSharedSandboxConfiguration) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// Bind and Render for IBMSharedSandboxConfigurations
func (p *IBMSharedSandboxConfigurations) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *IBMSharedSandboxConfiguration) Save() error {
	if p.ID != 0 {
		return p.Update()
	}

	// Insert resource and get Id
	if err := p.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO ibm_shared_account_configurations
			(name,
			apikey,
			annotations,
			valid,
			additional_vars)
			VALUES ($1, pgp_sym_encrypt($3::text, $2),$4, $5)
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

func (p *IBMSharedSandboxConfiguration) Update() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	// Update resource
	if _, err := p.DbPool.Exec(
		context.Background(),
		`UPDATE ibm_shared_account_configurations
		 SET name = $1,
			 apikey = pgp_sym_encrypt($3::text, $2),
			 annotations = $4,
			 valid = $5,
			 additional_vars = $6
		 WHERE id = $10`,
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

func (p *IBMSharedSandboxConfiguration) Delete() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM ibm_shared_account_configurations WHERE id = $1",
		p.ID,
	)
	return err
}

// Disable an IBMSharedSandboxConfiguration
func (p *IBMSharedSandboxConfiguration) Disable() error {
	p.Valid = false
	return p.Update()
}

// Enable an IBMSharedSandboxConfiguration
func (p *IBMSharedSandboxConfiguration) Enable() error {
	p.Valid = true
	return p.Update()
}

// CountAccounts returns the number of accounts for an IBMSharedSandboxConfiguration
func (p *IBMSharedSandboxConfiguration) GetAccountCount() (int, error) {
	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources WHERE resource_type = 'IBMSharedSandbox' AND resource_data->>'ibm_shared_account' = $1",
		p.Name,
	).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// GetIBMSharedSandboxConfigurationByName returns an IBMSharedSandboxConfiguration by name
func (p *IBMSharedSandboxProvider) GetIBMSharedSandboxConfigurationByName(name string) (IBMSharedSandboxConfiguration, error) {
	// Get resource from above 'ibm_shared_account_configurations' table
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
		 FROM ibm_shared_account_configurations WHERE name = $2`,
		p.VaultSecret, name,
	)

	var cluster IBMSharedSandboxConfiguration
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
		return IBMSharedSandboxConfiguration{}, err
	}
	cluster.DbPool = p.DbPool
	cluster.VaultSecret = p.VaultSecret
	return cluster, nil
}

// GetIBMSharedSandboxConfigurations returns the full list of IBMSharedSandboxConfiguration
func (p *IBMSharedSandboxProvider) GetIBMSharedSandboxConfigurations() (IBMSharedSandboxConfigurations, error) {
	clusters := []IBMSharedSandboxConfiguration{}

	// Get resource from 'ibm_shared_account_configurations' table
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
		 FROM ibm_shared_account_configurations`,
		p.VaultSecret,
	)

	if err != nil {
		return []IBMSharedSandboxConfiguration{}, err
	}

	for rows.Next() {
		var cluster IBMSharedSandboxConfiguration

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
			return []IBMSharedSandboxConfiguration{}, err
		}

		cluster.DbPool = p.DbPool
		cluster.VaultSecret = p.VaultSecret
		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

// GetIBMSharedSandboxConfigurationByAnnotations returns a list of IBMSharedSandboxConfiguration by annotations
func (p *IBMSharedSandboxProvider) GetIBMSharedSandboxConfigurationByAnnotations(annotations map[string]string) ([]IBMSharedSandboxConfiguration, error) {
	clusters := []IBMSharedSandboxConfiguration{}
	// Get resource from above 'ibm_shared_account_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT name FROM ibm_shared_account_configurations WHERE annotations @> $1`,
		annotations,
	)

	if err != nil {
		return []IBMSharedSandboxConfiguration{}, err
	}

	for rows.Next() {
		var clusterName string

		if err := rows.Scan(&clusterName); err != nil {
			return []IBMSharedSandboxConfiguration{}, err
		}

		cluster, err := p.GetIBMSharedSandboxConfigurationByName(clusterName)
		if err != nil {
			return []IBMSharedSandboxConfiguration{}, err
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

var IBMErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

func (a *IBMSharedSandbox) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *IBMSharedSandboxWithCreds) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *IBMSharedSandbox) Save(dbpool *pgxpool.Pool) error {
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

func (a *IBMSharedSandboxWithCreds) Update() error {

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

func (a *IBMSharedSandboxWithCreds) Save() error {
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

func (a *IBMSharedSandboxWithCreds) SetStatus(status string) error {
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

func (a *IBMSharedSandboxWithCreds) GetStatus() (string, error) {
	var status string
	err := a.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1",
		a.ID,
	).Scan(&status)

	return status, err
}

func (a *IBMSharedSandboxWithCreds) MarkForCleanup() error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' WHERE id = $1",
		a.ID,
	)

	return err
}

func (a *IBMSharedSandboxWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET cleanup_count = cleanup_count + 1 WHERE id = $1",
		a.ID,
	)

	return err
}
func (a *IBMSharedSandboxProvider) FetchAllByServiceUuid(serviceUuid string) ([]IBMSharedSandbox, error) {
	accounts := []IBMSharedSandbox{}
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
			COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		FROM
			resources r
		LEFT JOIN
			ibm_shared_account_configurations oc ON oc.name = r.resource_data->>'ibm_shared_account'
		WHERE r.service_uuid = $1 AND r.resource_type = 'IBMSharedSandbox'`,
		serviceUuid,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account IBMSharedSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.AccountAdditionalVars,
		); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (a *IBMSharedSandboxProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]IBMSharedSandboxWithCreds, error) {
	accounts := []IBMSharedSandboxWithCreds{}
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
			COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		FROM
			resources r
		LEFT JOIN
			ibm_shared_account_configurations oc ON oc.name = r.resource_data->>'ibm_shared_account'
		WHERE r.service_uuid = $1 AND r.resource_type = 'IBMSharedSandbox'`,
		serviceUuid, a.VaultSecret,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account IBMSharedSandboxWithCreds

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
			&account.AccountAdditionalVars,
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

var IBMErrNoSchedule error = errors.New("No IBM shared account configuration found")

func (a *IBMSharedSandboxProvider) GetSchedulableAccounts(cloud_selector map[string]string) (IBMSharedSandboxConfigurations, error) {
	clusters := IBMSharedSandboxConfigurations{}
	// Get resource from 'ibm_shared_account_configurations' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT name FROM ibm_shared_account_configurations WHERE annotations @> $1 and valid=true ORDER BY random()`,
		cloud_selector,
	)

	if err != nil {
		log.Logger.Error("Error querying ibm shared accounts", "error", err)
		return IBMSharedSandboxConfigurations{}, err
	}

	for rows.Next() {
		var clusterName string

		if err := rows.Scan(&clusterName); err != nil {
			return IBMSharedSandboxConfigurations{}, err
		}

		cluster, err := a.GetIBMSharedSandboxConfigurationByName(clusterName)
		if err != nil {
			return IBMSharedSandboxConfigurations{}, err
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

func (a *IBMSharedSandboxProvider) Request(serviceUuid string, cloud_selector map[string]string, annotations map[string]string, ctx context.Context) (IBMSharedSandboxWithCreds, error) {
	// Ensure annotation has guid
	if _, exists := annotations["guid"]; !exists {
		return IBMSharedSandboxWithCreds{}, errors.New("guid not found in annotations")
	}

	// Version with IBMSharedSandboxConfiguration methods
	candidateAccounts, err := a.GetSchedulableAccounts(cloud_selector)
	if err != nil {
		log.Logger.Error("Error getting shared accounts", "error", err)
		return IBMSharedSandboxWithCreds{}, err
	}
	if len(candidateAccounts) == 0 {
		log.Logger.Error("No IBM shared account configuration found", "cloud_selector", cloud_selector)
		return IBMSharedSandboxWithCreds{}, IBMErrNoSchedule
	}

	if len(candidateAccounts) > 1 {
		log.Logger.Error("More than one IBM shared account configuration found", "cloud_selector", cloud_selector)
		return IBMSharedSandboxWithCreds{}, IBMErrNoSchedule
	}

	// Determine guid, auto increment the guid if there are multiple resources
	// for a serviceUuid
	guid, err := IBMSharedSandboxGuessNextGuid(annotations["guid"], serviceUuid, a.DbPool, ctx)
	if err != nil {
		log.Logger.Error("Error guessing guid", "error", err)
		return IBMSharedSandboxWithCreds{}, err
	}
	// Return the Placement with a status 'initializing'
	rnew := IBMSharedSandboxWithCreds{
		IBMSharedSandbox: IBMSharedSandbox{
			Name:        guid + "-" + serviceUuid,
			Kind:        "IBMSharedSandbox",
			Annotations: annotations,
			ServiceUuid: serviceUuid,
			Status:      "initializing",
		},
		Provider: a,
	}

	rnew.Resource.CreatedAt = time.Now()
	rnew.Resource.UpdatedAt = time.Now()

	if err := rnew.Save(); err != nil {
		log.Logger.Error("Error saving IBM shared account", "error", err)
		return IBMSharedSandboxWithCreds{}, err
	}

	//--------------------------------------------------
	// The following is async
	go func() {
		selectedAccount := candidateAccounts[0]
		rnew.SetStatus("scheduling")
	  log.Logger.Info("Account", "name", selectedAccount.Name)

		rnew.IBMSharedSandboxConfigurationName = selectedAccount.Name

		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving IBM shared account", "error", err)
			rnew.SetStatus("error")
			return
		}

		suffix := annotations["resourcegroup_suffix"]
		if suffix == "" {
			suffix = serviceUuid
		}

		resourceGroupName := "shared-" + guid + "-" + suffix
		resourceGroupName = resourceGroupName[:min(40, len(resourceGroupName))] // truncate to 40

		authenticator, err := core.NewIamAuthenticatorBuilder().
				SetApiKey(selectedAccount.APIKey).
				Build()
		
		iamIdentityServiceOptions := &iamidentityv1.IamIdentityV1Options{Authenticator: authenticator}
		iamIdentityService, err := iamidentityv1.NewIamIdentityV1UsingExternalConfig(iamIdentityServiceOptions)
		options := iamIdentityService.NewGetAPIKeysDetailsOptions()
		options.SetIamAPIKey(selectedAccount.APIKey)
		userdetails, _, err := iamIdentityService.GetAPIKeysDetails(options)
		accountID := userdetails.AccountID
		createServiceIDOptions := iamIdentityService.NewCreateServiceIDOptions(*userdetails.AccountID, resourceGroupName)
		serviceID, response, err := iamIdentityService.CreateServiceID(createServiceIDOptions)
		iamID := *serviceID.IamID
		createAPIKeyOptions := iamIdentityService.NewCreateAPIKeyOptions("sandbox",  *serviceID.IamID)
		createAPIKeyOptions.SetDescription("Created by sandbox-api")
		apiKey, response, err := iamIdentityService.CreateAPIKey(createAPIKeyOptions)
		apiKeyValue := *apiKey.Apikey

		

		resourceManagerClientOptions := &resourcemanagerv2.ResourceManagerV2Options{Authenticator: authenticator}
		resourceManagerClient, err := resourcemanagerv2.NewResourceManagerV2UsingExternalConfig(resourceManagerClientOptions)
		resourceGroupCreate := resourcemanagerv2.CreateResourceGroupOptions{
			Name:      &resourceGroupName,
		}

		resCreateResourceGroup, response, err := resourceManagerClient.CreateResourceGroup(&resourceGroupCreate)
		fmt.Println(response)
		if err != nil {
			log.Logger.Error("Error creating Resource Group", "error", err)
			rnew.SetStatus("error")
			return
		}
		resourceGroupId := resCreateResourceGroup.ID	
		rnew.ResourceGroup = resourceGroupName
		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving IBM shared account", "error", err)
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
							Name:  core.StringPtr("accountId"),
							Value: accountID,
							Operator: core.StringPtr("stringEquals"),
						},
						{
							Name:  core.StringPtr("resourceGroupId"),
							Value: resourceGroupId,
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
							Name:  core.StringPtr("accountId"),
							Value: accountID,
							Operator: core.StringPtr("stringEquals"),
						},
						{
							Name:  core.StringPtr("resourceType"),
							Value: core.StringPtr("resource-group"),
							Operator: core.StringPtr("stringEquals"),
						},
						{
							Name:  core.StringPtr("resource"),
							Value: resourceGroupId,
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
		}

		// Print the result
		fmt.Printf("Policy created successfully: %v\n", *result.ID)

		result, response, err = iamPolicyManagementService.CreatePolicy(policyRG)
		if err != nil {
			log.Logger.Error("Failed to create policy: %v\nResponse: %v", err, response)
		}

		// Print the result
		fmt.Printf("Policy created successfully: %v\n", *result.ID)

		creds := []any{
			IBMSharedServiceAccount{
				Name:  resourceGroupName,
				APIKey: apiKeyValue,
			},
		}
		rnew.Credentials = creds
		rnew.Status = "success"

		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving IBM shared account", "error", err)
			log.Logger.Info("Trying to cleanup IBM shared account")
			if err := rnew.Delete(); err != nil {
				log.Logger.Error("Error cleaning up IBM shared account", "error", err)
			}
		}
		log.Logger.Info("IBM sandbox booked", "account", rnew.Name, "service_uuid", rnew.ServiceUuid,
			"cluster", rnew.IBMSharedSandboxConfigurationName, "resourcegroup", rnew.ResourceGroup)
	}()
	//--------------------------------------------------

	return rnew, nil
}

func IBMSharedSandboxGuessNextGuid(origGuid string, serviceUuid string, dbpool *pgxpool.Pool, ctx context.Context) (string, error) {
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
			AND resource_type = 'IBMSharedSandbox'`,
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

func (a *IBMSharedSandboxProvider) Release(service_uuid string) error {
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

func NewIBMSharedSandboxProvider(dbpool *pgxpool.Pool, vaultSecret string) IBMSharedSandboxProvider {
	return IBMSharedSandboxProvider{
		DbPool:      dbpool,
		VaultSecret: vaultSecret,
	}
}

func (a *IBMSharedSandboxProvider) FetchAll() ([]IBMSharedSandbox, error) {
	accounts := []IBMSharedSandbox{}
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
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ibm_shared_account_configurations oc ON oc.name = r.resource_data->>'ibm_shared_account' 
		 WHERE r.resource_type = 'IBMSharedSandbox'`,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account IBMSharedSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.AccountAdditionalVars,
		); err != nil {
			return accounts, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (account *IBMSharedSandboxWithCreds) Delete() error {

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

	if account.IBMSharedSandboxConfigurationName == "" {
		// Get the IBM shared account configuration name from the resources.resource_data column using ID
		err := account.Provider.DbPool.QueryRow(
			context.Background(),
			"SELECT resource_data->>'ibm_shared_account' FROM resources WHERE id = $1",
			account.ID,
		).Scan(&account.IBMSharedSandboxConfigurationName)

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

	if account.IBMSharedSandboxConfigurationName == "" {
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

	// Get the IBM shared account configuration from the resources.resource_data column

	ibmSharedAccount, err := account.Provider.GetIBMSharedSandboxConfigurationByName(account.IBMSharedSandboxConfigurationName)
	if err != nil {
		log.Logger.Error("Error getting IBM shared account configuration", "error", err)
		account.SetStatus("error")
		return err
	}
	log.Logger.Info("TODO", "account", ibmSharedAccount)
  authenticator, err := core.NewIamAuthenticatorBuilder().
		SetApiKey(ibmSharedAccount.APIKey).
		Build()

	resourceControllerServiceOptions := &resourcecontrollerv2.ResourceControllerV2Options{Authenticator: authenticator}
	resourceControllerService, err := resourcecontrollerv2.NewResourceControllerV2UsingExternalConfig(resourceControllerServiceOptions)

	resourceManagerClientOptions := &resourcemanagerv2.ResourceManagerV2Options{Authenticator: authenticator}
	resourceManagerClient, err := resourcemanagerv2.NewResourceManagerV2UsingExternalConfig(resourceManagerClientOptions)
	resourceGroupOptions := resourcemanagerv2.ListResourceGroupsOptions{
		Name:      &account.ResourceGroup,
  }


	resourceGroup, _, err := resourceManagerClient.ListResourceGroups(&resourceGroupOptions)
	if err != nil {
		panic(err)
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
				panic(err)
			}

			var allResults []resourcecontrollerv2.ResourceInstance
			for pager.HasNext() {
				nextPage, err := pager.GetNext()
				if err != nil {
					panic(err)
				}
				allResults = append(allResults, nextPage...)
			}
			b, _ := json.MarshalIndent(allResults, "", "  ")
			fmt.Println(string(b))
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
					log.Logger.Error("Failed to delete resource instance with IDxx %s: %v", *instance.ID, err)
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
			panic(err)
		}
	}
  iamIdentityServiceOptions := &iamidentityv1.IamIdentityV1Options{Authenticator: authenticator}
	iamIdentityService, err := iamidentityv1.NewIamIdentityV1UsingExternalConfig(iamIdentityServiceOptions)
  options := iamIdentityService.NewGetAPIKeysDetailsOptions()
	options.SetIamAPIKey(ibmSharedAccount.APIKey)
	userdetails, _, err := iamIdentityService.GetAPIKeysDetails(options)
	accountID := userdetails.AccountID

	listServiceIDOptions := &iamidentityv1.ListServiceIdsOptions{AccountID: accountID, Name: &account.Name}
	services, response, err := iamIdentityService.ListServiceIds(listServiceIDOptions)
  b, _ := json.MarshalIndent(response, "", "  ")
	fmt.Println(string(b))
	if services != nil && len(services.Serviceids) > 0 {
		deleteServiceIDOptions := iamIdentityService.NewDeleteServiceIDOptions(*services.Serviceids[0].ID)
		_, err = iamIdentityService.DeleteServiceID(deleteServiceIDOptions)
		if err != nil {
				panic(err)
		}
	}

	// TODO
	log.Logger.Info("ResourceGroup deleted",
		"name", account.Name,
		"resourcegroup", account.ResourceGroup,
		"cluster", account.IBMSharedSandboxConfigurationName,
	)
	_, err = account.Provider.DbPool.Exec(
		context.Background(),
		"DELETE FROM resources WHERE id = $1",
		account.ID,
	)
	return err
}

func (p *IBMSharedSandboxProvider) FetchByName(name string) (IBMSharedSandbox, error) {
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
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ibm_shared_account_configurations oc ON oc.name = resource_data->>'ibm_shared_account'
		 WHERE r.resource_name = $1 AND r.resource_type = 'IBMSharedSandbox'`,
		name,
	)

	var account IBMSharedSandbox
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&account.AccountAdditionalVars,
	); err != nil {
		return IBMSharedSandbox{}, err
	}
	return account, nil
}

func (p *IBMSharedSandboxProvider) FetchById(id int) (IBMSharedSandbox, error) {
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
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ibm_shared_account_configurations oc ON oc.name = resource_data->>'ibm_shared_account'
		 WHERE r.id = $1`,
		id,
	)

	var account IBMSharedSandbox
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&account.AccountAdditionalVars,
	); err != nil {
		return IBMSharedSandbox{}, err
	}
	return account, nil
}

func (a *IBMSharedSandboxWithCreds) Reload() error {
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
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ibm_shared_account_configurations oc ON oc.name = resource_data->>'ibm_shared_account'
		 WHERE r.id = $1  AND r.resource_type = 'IBMSharedSandbox'`,
		a.ID, a.Provider.VaultSecret,
	)

	var creds string
	var account IBMSharedSandboxWithCreds
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
		&account.AccountAdditionalVars,
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
