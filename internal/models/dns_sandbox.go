package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DNSSandboxProvider struct {
	DbPool      *pgxpool.Pool `json:"-"`
	VaultSecret string        `json:"-"`
}

type DNSAccountConfiguration struct {
	ID                 int               `json:"id"`
	Name               string            `json:"name"`
	AwsAccessKeyID     string            `json:"aws_access_key_id"`
	AwsSecretAccessKey string            `json:"aws_secret_access_key"`
	Zone               string            `json:"zone"`
	HostedZoneID       string            `json:"hosted_zone_id"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	Annotations        map[string]string `json:"annotations"`
	Valid              bool              `json:"valid"`
	AdditionalVars     map[string]any    `json:"additional_vars,omitempty"`
	DbPool             *pgxpool.Pool     `json:"-"`
	VaultSecret        string            `json:"-"`
}

type DNSAccountConfigurations []DNSAccountConfiguration

type DNSSandbox struct {
	Account
	Name                        string            `json:"name"`
	Kind                        string            `json:"kind"` // "DNSSandbox"
	ServiceUuid                 string            `json:"service_uuid"`
	DNSAccountConfigurationName string            `json:"dns_account"`
	Annotations                 map[string]string `json:"annotations"`
	Status                      string            `json:"status"`
	ErrorMessage                string            `json:"error_message,omitempty"`
	CleanupCount                int               `json:"cleanup_count"`
	AdditionalVars              map[string]any    `json:"additional_vars,omitempty"`
	ToCleanup                   bool              `json:"to_cleanup"`
}

type DNSSandboxWithCreds struct {
	DNSSandbox

	Credentials []any               `json:"credentials,omitempty"`
	Provider    *DNSSandboxProvider `json:"-"`
}

// Credential for service account
type DNSServiceAccount struct {
	Kind               string `json:"kind"` // "DNSServiceAccount"
	AwsAccessKeyID     string `json:"aws_access_key_id"`
	AwsSecretAccessKey string `json:"aws_secret_access_key"`
	Zone               string `json:"zone"`
	HostedZoneID       string `json:"hosted_zone_id"`
}

type DNSSandboxes []DNSSandbox

var DNSnameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// MakeDNSAccountConfiguration creates a new DNSAccountConfiguration
// with default values
func MakeDNSAccountConfiguration() *DNSAccountConfiguration {
	p := &DNSAccountConfiguration{}

	p.Valid = true
	return p
}

// PolicyDocument defines a policy document as a Go struct that can be serialized
// to JSON.
type PolicyDocument struct {
	Version   string
	Statement []PolicyStatement
}

// PolicyStatement defines a statement in a policy document.
type PolicyStatement struct {
	Effect    string            `json:"Effect"`
	Action    interface{}       `json:"Action"`
	Principal map[string]string `json:",omitempty"`
	Resource  interface{}       `json:",omitempty"`
}

func isNoSuchEntityErrorIam(err error) bool {
	var notFound *iamtypes.NoSuchEntityException
	return err != nil && errors.As(err, &notFound)
}

// Bind and Render
func (p *DNSAccountConfiguration) Bind(r *http.Request) error {
	// Ensure the name is not empty
	if p.Name == "" {
		return errors.New("name is required")
	}

	// Ensure the name is valid
	if !DNSnameRegex.MatchString(p.Name) {
		return errors.New("name is invalid, must be only alphanumeric and '-'")
	}

	// Ensure zone is not empty
	if p.Zone == "" {
		return errors.New("zone is required")
	}

	// Ensure HostedZoneID is not empty
	if p.HostedZoneID == "" {
		return errors.New("HostedZoneID is required")
	}

	// Ensure AwsAccessKeyID and AwsSecretAccessKey are not empty
	if p.AwsAccessKeyID == "" || p.AwsSecretAccessKey == "" {
		return errors.New("AwsAccessKeyID and AwsSecretAccessKey must be defined")
	}

	if len(p.Annotations) == 0 {
		return errors.New("annotations is required")
	}

	return nil
}

func (p *DNSAccountConfiguration) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// Bind and Render for DNSAccountConfigurations
func (p *DNSAccountConfigurations) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *DNSAccountConfiguration) Save() error {
	if p.ID != 0 {
		return p.Update()
	}

	// Insert resource and get Id
	if err := p.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO dns_account_configurations
			(name,
			aws_access_key_id,
			aws_secret_access_key,
			zone,
			hosted_zone_id,
			annotations,
			valid,
			additional_vars)
			VALUES ($1, $2, pgp_sym_encrypt($3::text, $4), $5, $6, $7, $8, $9)
			RETURNING id`,
		p.Name,
		p.AwsAccessKeyID,
		p.AwsSecretAccessKey,
		p.VaultSecret,
		p.Zone,
		p.HostedZoneID,
		p.Annotations,
		p.Valid,
		p.AdditionalVars,
	).Scan(&p.ID); err != nil {
		return err
	}
	return nil
}

func (p *DNSAccountConfiguration) Update() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	// Update resource
	if _, err := p.DbPool.Exec(
		context.Background(),
		`UPDATE dns_account_configurations
		 SET name = $1,
			 aws_access_key_id = $2,
			 aws_secret_access_key = pgp_sym_encrypt($3::text, $4),
			 annotations = $5,
			 valid = $6,
			 additional_vars = $7
		 WHERE id = $8`,
		p.Name,
		p.AwsAccessKeyID,
		p.AwsSecretAccessKey,
		p.VaultSecret,
		p.Annotations,
		p.Valid,
		p.AdditionalVars,
		p.ID,
	); err != nil {
		return err
	}
	return nil
}

func (p *DNSAccountConfiguration) Delete() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM dns_account_configurations WHERE id = $1",
		p.ID,
	)
	return err
}

// Disable an DNSAccountConfiguration
func (p *DNSAccountConfiguration) Disable() error {
	p.Valid = false
	return p.Update()
}

// Enable an DNSAccountConfiguration
func (p *DNSAccountConfiguration) Enable() error {
	p.Valid = true
	return p.Update()
}

// CountAccounts returns the number of accounts for an DNSAccountConfiguration
func (p *DNSAccountConfiguration) GetAccountCount() (int, error) {
	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources WHERE resource_type = 'DNSSandbox' AND resource_data->>'dns_account' = $1",
		p.Name,
	).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// GetDNSAccountConfigurationByName returns an DNSAccountConfiguration by name
func (p *DNSSandboxProvider) GetDNSAccountConfigurationByName(name string) (DNSAccountConfiguration, error) {
	// Get resource from above 'dns_account_configurations' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
			id,
			name,
			aws_access_key_id,
			pgp_sym_decrypt(aws_secret_access_key::bytea, $1),
			zone,
			hosted_zone_id,
			created_at,
			updated_at,
			annotations,
			valid,
			additional_vars
		 FROM dns_account_configurations WHERE name = $2`,
		p.VaultSecret, name,
	)

	var account DNSAccountConfiguration
	if err := row.Scan(
		&account.ID,
		&account.Name,
		&account.AwsAccessKeyID,
		&account.AwsSecretAccessKey,
		&account.Zone,
		&account.HostedZoneID,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Annotations,
		&account.Valid,
		&account.AdditionalVars,
	); err != nil {
		return DNSAccountConfiguration{}, err
	}
	account.DbPool = p.DbPool
	account.VaultSecret = p.VaultSecret
	return account, nil
}

// GetDNSAccountConfigurations returns the full list of DNSAccountConfiguration
func (p *DNSSandboxProvider) GetDNSAccountConfigurations() (DNSAccountConfigurations, error) {
	accounts := []DNSAccountConfiguration{}

	// Get resource from 'dns_account_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT
			id,
			name,
			aws_access_key_id,
			pgp_sym_decrypt(aws_secret_access_key::bytea, $1),
			zone,
			hosted_zone_id,
			created_at,
			updated_at,
			annotations,
			valid,
			additional_vars
		 FROM dns_account_configurations`,
		p.VaultSecret,
	)

	if err != nil {
		return []DNSAccountConfiguration{}, err
	}

	for rows.Next() {
		var account DNSAccountConfiguration

		if err := rows.Scan(
			&account.ID,
			&account.Name,
			&account.AwsAccessKeyID,
			&account.AwsSecretAccessKey,
			&account.Zone,
			&account.HostedZoneID,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Annotations,
			&account.Valid,
			&account.AdditionalVars,
		); err != nil {
			return []DNSAccountConfiguration{}, err
		}

		account.DbPool = p.DbPool
		account.VaultSecret = p.VaultSecret
		accounts = append(accounts, account)
	}

	return accounts, nil
}

// GetDNSAccountConfigurationByAnnotations returns a list of DNSAccountConfiguration by annotations
func (p *DNSSandboxProvider) GetDNSAccountConfigurationByAnnotations(annotations map[string]string) ([]DNSAccountConfiguration, error) {
	accounts := []DNSAccountConfiguration{}
	// Get resource from above 'dns_account_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT name FROM dns_account_configurations WHERE annotations @> $1`,
		annotations,
	)

	if err != nil {
		return []DNSAccountConfiguration{}, err
	}

	for rows.Next() {
		var accountName string

		if err := rows.Scan(&accountName); err != nil {
			return []DNSAccountConfiguration{}, err
		}

		account, err := p.GetDNSAccountConfigurationByName(accountName)
		if err != nil {
			return []DNSAccountConfiguration{}, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

var DNSErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

func (a *DNSSandbox) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *DNSSandboxWithCreds) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *DNSSandbox) Save(dbpool *pgxpool.Pool) error {
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

func (a *DNSSandboxWithCreds) Update() error {

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

func (a *DNSSandboxWithCreds) Save() error {
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

func (a *DNSSandboxWithCreds) SetStatus(status string) error {
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

func (a *DNSSandboxWithCreds) GetStatus() (string, error) {
	var status string
	err := a.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1",
		a.ID,
	).Scan(&status)

	return status, err
}

func (a *DNSSandboxWithCreds) MarkForCleanup() error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true, resource_data['to_cleanup'] = 'true' WHERE id = $1",
		a.ID,
	)

	return err
}

func (a *DNSSandboxWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET cleanup_count = cleanup_count + 1 WHERE id = $1",
		a.ID,
	)

	return err
}
func (a *DNSSandboxProvider) FetchAllByServiceUuid(serviceUuid string) ([]DNSSandbox, error) {
	accounts := []DNSSandbox{}
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
		FROM
			resources r
		LEFT JOIN
			dns_account_configurations oc ON oc.name = r.resource_data->>'dns_account'
		WHERE r.service_uuid = $1 AND r.resource_type = 'DNSSandbox'`,
		serviceUuid,
	)

	if err != nil {
		return accounts, err
	}

	for rows.Next() {
		var account DNSSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.AdditionalVars,
		); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (a *DNSSandboxProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]DNSSandboxWithCreds, error) {
	sandboxes := []DNSSandboxWithCreds{}
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
			COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		FROM
			resources r
		LEFT JOIN
			dns_account_configurations oc ON oc.name = r.resource_data->>'dns_account'
		WHERE r.service_uuid = $1 AND r.resource_type = 'DNSSandbox'`,
		serviceUuid, a.VaultSecret,
	)

	if err != nil {
		return sandboxes, err
	}

	for rows.Next() {
		var sandbox DNSSandboxWithCreds

		creds := ""
		if err := rows.Scan(
			&sandbox,
			&sandbox.ID,
			&sandbox.Name,
			&sandbox.Kind,
			&sandbox.CreatedAt,
			&sandbox.UpdatedAt,
			&sandbox.Status,
			&sandbox.CleanupCount,
			&creds,
			&sandbox.AdditionalVars,
		); err != nil {
			return sandboxes, err
		}
		// Unmarshal creds into sandbox.Credentials
		if err := json.Unmarshal([]byte(creds), &sandbox.Credentials); err != nil {
			return sandboxes, err
		}

		sandbox.ServiceUuid = serviceUuid
		sandbox.Provider = a

		sandboxes = append(sandboxes, sandbox)
	}

	return sandboxes, nil
}

var DNSErrNoSchedule error = errors.New("No DNS account configuration found")

func (a *DNSSandboxProvider) GetSchedulableAccounts(cloud_selector map[string]string) (DNSAccountConfigurations, error) {
	accounts := DNSAccountConfigurations{}
	// Get resource from 'dns_account_configurations' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT name FROM dns_account_configurations WHERE annotations @> $1 and valid=true ORDER BY random()`,
		cloud_selector,
	)

	if err != nil {
		log.Logger.Error("Error querying ocp accounts", "error", err)
		return DNSAccountConfigurations{}, err
	}

	for rows.Next() {
		var accountName string

		if err := rows.Scan(&accountName); err != nil {
			return DNSAccountConfigurations{}, err
		}

		account, err := a.GetDNSAccountConfigurationByName(accountName)
		if err != nil {
			return DNSAccountConfigurations{}, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (a *DNSSandboxProvider) Request(serviceUuid string, cloud_selector map[string]string, annotations map[string]string, multiple bool, ctx context.Context) (DNSSandboxWithCreds, error) {
	if _, exists := annotations["guid"]; !exists {
		return DNSSandboxWithCreds{}, errors.New("guid not found in annotations")
	}

	// Version with DNSAccountConfiguration methods
	candidateAccounts, err := a.GetSchedulableAccounts(cloud_selector)
	if err != nil {
		log.Logger.Error("Error getting schedulable accounts", "error", err)
		return DNSSandboxWithCreds{}, err
	}
	if len(candidateAccounts) == 0 {
		log.Logger.Error("No DNS account configuration found", "cloud_selector", cloud_selector)
		return DNSSandboxWithCreds{}, DNSErrNoSchedule
	}

	var selectedAccount = candidateAccounts[0]

	// Determine guid, auto increment the guid if there are multiple resources
	// for a serviceUuid
	guid, err := DNSguessNextGuid(annotations["guid"], serviceUuid, a.DbPool, multiple, ctx)
	if err != nil {
		log.Logger.Error("Error guessing guid", "error", err)
		return DNSSandboxWithCreds{}, err
	}

	suffix := annotations["sandbox_suffix"]
	if suffix != "" {
		guid = guid + "-" + suffix
	}
	// Return the Placement with a status 'initializing'
	rnew := DNSSandboxWithCreds{
		DNSSandbox: DNSSandbox{
			Name:        guid,
			Kind:        "DNSSandbox",
			Annotations: annotations,
			ServiceUuid: serviceUuid,
			Status:      "initializing",
		},
		Provider: a,
	}
	rnew.DNSAccountConfigurationName = selectedAccount.Name
	rnew.Resource.CreatedAt = time.Now()
	rnew.Resource.UpdatedAt = time.Now()
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Logger.Error("Error loading config", "error", err)
		return rnew, err
	}
	accountCreds := credentials.StaticCredentialsProvider{
		Value: aws.Credentials{
			AccessKeyID:     selectedAccount.AwsAccessKeyID,
			SecretAccessKey: selectedAccount.AwsSecretAccessKey,
		},
	}
	route53Client := route53.NewFromConfig(
		cfg,
		func(o *route53.Options) {
			o.Credentials = accountCreds
		},
	)
	domain := guid + "." + selectedAccount.Zone
	domainCreateInput := &route53.CreateHostedZoneInput{
		Name:            &domain,
		CallerReference: aws.String(strconv.FormatInt(time.Now().UnixNano(), 10)),
	}

	responseCreate, err := route53Client.CreateHostedZone(ctx, domainCreateInput)
	if err != nil {
		log.Logger.Error("Error creating Hosted Zone", "error", err)
		return DNSSandboxWithCreds{}, err
	}
	var nsRecords []route53types.ResourceRecord
	for _, nameserver := range responseCreate.DelegationSet.NameServers {
		nsRecords = append(nsRecords, route53types.ResourceRecord{
			Value: &nameserver,
		})
	}
	var changes []route53types.Change
	changes = append(changes, route53types.Change{
		Action: route53types.ChangeActionCreate,
		ResourceRecordSet: &route53types.ResourceRecordSet{
			Name:            &domain,
			Type:            "NS",
			TTL:             aws.Int64(3600),
			ResourceRecords: nsRecords,
		},
	})
	changeBatch := &route53types.ChangeBatch{
		Changes: changes,
	}
	recordsChangeInput := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch:  changeBatch,
		HostedZoneId: &selectedAccount.HostedZoneID,
	}

	_, err = route53Client.ChangeResourceRecordSets(ctx, recordsChangeInput)
	if err != nil {
		log.Logger.Error("Error changing resource record sets", "error", err)
		return DNSSandboxWithCreds{}, err
	}

	iamClient := iam.NewFromConfig(
		cfg,
		func(o *iam.Options) {
			o.Credentials = accountCreds
		},
	)

	responseCreateUser, err := iamClient.CreateUser(ctx, &iam.CreateUserInput{
		UserName: aws.String(guid),
	})
	if err != nil {
		log.Logger.Error("Error creating user", "error", err, "response", responseCreateUser)
		return DNSSandboxWithCreds{}, err
	}
	var accesskey *iamtypes.AccessKey
	responseCreateAccessKey, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: aws.String(guid)})
	if err != nil {
		log.Logger.Error("Error creating Access Key", "error", err)
		return DNSSandboxWithCreds{}, err
	} else {
		accesskey = responseCreateAccessKey.AccessKey
		log.Logger.Info("responseCreateAccessKey", "AccessKey", accesskey)
	}
	policyDoc := PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Action:   "route53:GetHostedZone",
				Resource: "arn:aws:route53:::change/*",
				Effect:   "Allow",
			},
			{
				Action: []string{
					"route53:ChangeResourceRecordSets",
					"route53:ListResourceRecordSets",
					"route53:GetHostedZone"},
				Resource: "arn:aws:route53:::hostedzone/" + strings.Split(*responseCreate.HostedZone.Id, "/")[2],
				Effect:   "Allow",
			},
			{
				Action:   "route53:GetChange",
				Resource: "arn:aws:route53:::change/*",
				Effect:   "Allow",
			},
		},
	}
	policyBytes, err := json.Marshal(policyDoc)
	if err != nil {
		log.Logger.Error("Couldn't create policy document", "error", err)
		return DNSSandboxWithCreds{}, err
	}
	_, err = iamClient.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
		PolicyDocument: aws.String(string(policyBytes)),
		PolicyName:     aws.String(guid),
		UserName:       aws.String(guid),
	})
	if err != nil {
		log.Logger.Error("Couldn't create policy", "error", err)
		return DNSSandboxWithCreds{}, err
	}

	creds := []any{
		DNSServiceAccount{
			Kind:               "Route53",
			AwsAccessKeyID:     *accesskey.AccessKeyId,
			AwsSecretAccessKey: *accesskey.SecretAccessKey,
			Zone:               domain,
			HostedZoneID:       strings.Split(*responseCreate.HostedZone.Id, "/")[2],
		},
	}
	rnew.Credentials = creds
	rnew.Status = "success"

	if err := rnew.Save(); err != nil {
		log.Logger.Error("Error saving DNS account", "error", err)
		return DNSSandboxWithCreds{}, err
	}

	return rnew, nil
}

func DNSguessNextGuid(origGuid string, serviceUuid string, dbpool *pgxpool.Pool, multiple bool, ctx context.Context) (string, error) {
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
			AND resource_type = 'DNSSandbox'`,
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

func (a *DNSSandboxProvider) Release(service_uuid string) error {
	sandboxes, err := a.FetchAllByServiceUuidWithCreds(service_uuid)

	if err != nil {
		return err
	}

	var errorHappened error

	for _, sandbox := range sandboxes {
		if sandbox.DNSAccountConfigurationName == "" &&
			sandbox.Status != "error" &&
			sandbox.Status != "scheduling" &&
			sandbox.Status != "initializing" {
			// If the sandbox is not in error and the namespace is empty, throw an error
			errorHappened = errors.New("DNSAccountConfigurationName not found for sandbox")
			log.Logger.Error("DNSAccountConfigurationName not found for sandbox", "sandbox", sandbox)
			continue
		}

		if err := sandbox.Delete(); err != nil {
			errorHappened = err
			continue
		}
	}
	return errorHappened
}

func NewDNSSandboxProvider(dbpool *pgxpool.Pool, vaultSecret string) DNSSandboxProvider {
	return DNSSandboxProvider{
		DbPool:      dbpool,
		VaultSecret: vaultSecret,
	}
}

func (a *DNSSandboxProvider) FetchAll() ([]DNSSandbox, error) {
	sandboxes := []DNSSandbox{}
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
		 LEFT JOIN dns_account_configurations oc ON oc.name = r.resource_data->>'dns_account' AND r.resource_type = 'DNSSandbox'`,
	)

	if err != nil {
		return sandboxes, err
	}

	for rows.Next() {
		var sandbox DNSSandbox
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

func (sandbox *DNSSandboxWithCreds) Delete() error {

	if sandbox.ID == 0 {
		return errors.New("resource ID must be > 0")
	}

	maxRetries := 10
	for {
		status, err := sandbox.GetStatus()
		if err != nil {
			// if norow, the resource was not created, nothing to delete
			if err == pgx.ErrNoRows {
				log.Logger.Info("Resource not found", "name", sandbox.Name)
				return nil
			}
			log.Logger.Error("cannot get status of resource", "error", err, "name", sandbox.Name)
			break
		}
		if maxRetries == 0 {
			log.Logger.Error("Resource is not in a final state", "name", sandbox.Name, "status", status)

			// Curative and auto-healing action, set status to error
			if status == "initializing" || status == "scheduling" {
				if err := sandbox.SetStatus("error"); err != nil {
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

	// Reload sandbox
	if err := sandbox.Reload(); err != nil {
		log.Logger.Error("Error reloading sandbox", "error", err)
		return err
	}

	if sandbox.DNSAccountConfigurationName == "" {
		// Get the DNS sandbox configuration name from the resources.resource_data column using ID
		err := sandbox.Provider.DbPool.QueryRow(
			context.Background(),
			"SELECT resource_data->>'dns_sandbox' FROM resources WHERE id = $1",
			sandbox.ID,
		).Scan(&sandbox.DNSAccountConfigurationName)

		if err != nil {
			if err == pgx.ErrNoRows {
				log.Logger.Error("DNS sandbox doesn't exist for resource", "name", sandbox.Name)
				sandbox.SetStatus("error")
				return errors.New("DNS sandbox doesn't exist for resource")
			}

			log.Logger.Error("DNS sandbox query error", "err", err)
			sandbox.SetStatus("error")
			return err
		}
	}

	if sandbox.DNSAccountConfigurationName == "" {
		// The resource was not created, nothing to delete
		// that happens when no sandbox is elected
		_, err := sandbox.Provider.DbPool.Exec(
			context.Background(),
			"DELETE FROM resources WHERE id = $1",
			sandbox.ID,
		)
		return err
	}

	sandbox.SetStatus("deleting")
	// In case anything goes wrong, we'll know it can safely be deleted
	sandbox.MarkForCleanup()
	sandbox.IncrementCleanupCount()

	dnsaccount, err := sandbox.Provider.GetDNSAccountConfigurationByName(sandbox.DNSAccountConfigurationName)
	if err != nil {
		log.Logger.Error("Error getting DNS account configuration", "error", err)
		sandbox.SetStatus("error")
		return err
	}
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Logger.Error("Error loading config", "error", err)
		sandbox.SetStatus("error")
		return err
	}
	sandboxCreds := credentials.StaticCredentialsProvider{
		Value: aws.Credentials{
			AccessKeyID:     dnsaccount.AwsAccessKeyID,
			SecretAccessKey: dnsaccount.AwsSecretAccessKey,
		},
	}
	route53Client := route53.NewFromConfig(
		cfg,
		func(o *route53.Options) {
			o.Credentials = sandboxCreds
		},
	)

	var credsSandbox map[string]interface{}
	credsSandbox = sandbox.Credentials[0].(map[string]interface{})
	domain := credsSandbox["zone"].(string)
	responseListResourceRecordSets, err := route53Client.ListResourceRecordSets(context.TODO(), &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(dnsaccount.HostedZoneID),
		StartRecordName: &domain,
		StartRecordType: "NS",
		MaxItems:        aws.Int32(1),
	})

	if err != nil {
		log.Logger.Error("Error listing resource record sets", "error", err)
		return err
	}

	if len(responseListResourceRecordSets.ResourceRecordSets) > 0 && *responseListResourceRecordSets.ResourceRecordSets[0].Name == domain+"." {
		var changes []route53types.Change
		changes = append(changes, route53types.Change{
			Action:            route53types.ChangeActionDelete,
			ResourceRecordSet: &responseListResourceRecordSets.ResourceRecordSets[0],
		})
		changeBatch := &route53types.ChangeBatch{
			Changes: changes,
		}
		recordsChangeInput := &route53.ChangeResourceRecordSetsInput{
			ChangeBatch:  changeBatch,
			HostedZoneId: &dnsaccount.HostedZoneID,
		}

		_, err = route53Client.ChangeResourceRecordSets(context.TODO(), recordsChangeInput)
		if err != nil {
			log.Logger.Error("Error deleting resource record sets", "error", err)
			return err
		}
	}

	domainListInput := &route53.ListHostedZonesByNameInput{
		DNSName: &domain,
	}

	responseList, err := route53Client.ListHostedZonesByName(context.TODO(), domainListInput)
	if err != nil {
		log.Logger.Error("Error listing Hosted Zone", "error", err)
		return err
	}
	if len(responseList.HostedZones) == 0 {
		log.Logger.Info("No HostedZone found, continue")
	} else {
		hostedZoneId := responseList.HostedZones[0].Id

		listResourcesInput := &route53.ListResourceRecordSetsInput{
			HostedZoneId: hostedZoneId,
		}

		var changes []route53types.Change

		for {
			resp, err := route53Client.ListResourceRecordSets(context.TODO(), listResourcesInput)
			if err != nil {
				log.Logger.Error("Error listing records", "error", err)
				return err
			}

			for _, record := range resp.ResourceRecordSets {
				if record.Type == route53types.RRTypeNs || record.Type == route53types.RRTypeSoa {
					continue
				}

				// Prepare a delete change for each record
				changes = append(changes, route53types.Change{
					Action:            route53types.ChangeActionDelete,
					ResourceRecordSet: &record,
				})
			}

			// Pagination logic
			if !resp.IsTruncated {
				break
			}

			listResourcesInput.StartRecordName = resp.NextRecordName
			listResourcesInput.StartRecordType = resp.NextRecordType
		}

		if len(changes) > 0 {
			changeResourcesInput := &route53.ChangeResourceRecordSetsInput{
				HostedZoneId: hostedZoneId,
				ChangeBatch: &route53types.ChangeBatch{
					Changes: changes,
				},
			}

			_, err = route53Client.ChangeResourceRecordSets(context.TODO(), changeResourcesInput)
			if err != nil {
				return fmt.Errorf("failed to delete records: %w", err)
			}
		}

		domainDeleteInput := &route53.DeleteHostedZoneInput{
			Id: hostedZoneId,
		}
		_, err := route53Client.DeleteHostedZone(context.TODO(), domainDeleteInput)
		if err != nil {
			log.Logger.Error("Error deleting Hosted Zone", "error", err)
			return err
		}
	}

	log.Logger.Info("Deleting", "user", sandbox.Name)
	iamClient := iam.NewFromConfig(
		cfg,
		func(o *iam.Options) {
			o.Credentials = sandboxCreds
		},
	)

	_, err = iamClient.GetUser(context.TODO(), &iam.GetUserInput{
		UserName: aws.String(sandbox.Name),
	})
	if err != nil {
		if isNoSuchEntityErrorIam(err) {
			log.Logger.Info("User does not exist. No action taken.")
		}
	} else {
		listKeysOutput, err := iamClient.ListAccessKeys(context.TODO(), &iam.ListAccessKeysInput{
			UserName: aws.String(sandbox.Name),
		})
		for _, accessKey := range listKeysOutput.AccessKeyMetadata {
			_, err := iamClient.DeleteAccessKey(context.TODO(), &iam.DeleteAccessKeyInput{
				UserName:    aws.String(sandbox.Name),
				AccessKeyId: accessKey.AccessKeyId,
			})
			if err != nil {
				log.Logger.Error("Error deleting access key", "error", err)
				return err
			}
		}

		listPoliciesOutput, err := iamClient.ListUserPolicies(context.TODO(), &iam.ListUserPoliciesInput{
			UserName: aws.String(sandbox.Name),
		})
		for _, policyName := range listPoliciesOutput.PolicyNames {
			_, err := iamClient.DeleteUserPolicy(context.TODO(), &iam.DeleteUserPolicyInput{
				UserName:   aws.String(sandbox.Name),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				log.Logger.Error("Error deleting policy user", "error", err)
				return err
			}
		}
		_, err = iamClient.DeleteUser(context.TODO(), &iam.DeleteUserInput{
			UserName: aws.String(sandbox.Name),
		})
		if err != nil {
			log.Logger.Error("Error deleting user", "error", err)
			return err
		}
	}
	_, err = sandbox.Provider.DbPool.Exec(
		context.Background(),
		"DELETE FROM resources WHERE id = $1",
		sandbox.ID,
	)
	return err
}

func (p *DNSSandboxProvider) FetchByName(name string) (DNSSandbox, error) {
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
		 LEFT JOIN dns_account_configurations oc ON oc.name = resource_data->>'dns_account'
		 WHERE r.resource_name = $1 and r.resource_type = 'DNSSandbox'`,
		name,
	)

	var sandbox DNSSandbox
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
		return DNSSandbox{}, err
	}
	return sandbox, nil
}

func (p *DNSSandboxProvider) FetchById(id int) (DNSSandbox, error) {
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
		 LEFT JOIN dns_account_configurations oc ON oc.name = resource_data->>'dns_account'
		 WHERE r.id = $1 AND r.resource_type = 'DNSSandbox'`,
		id,
	)

	var sandbox DNSSandbox
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
		return DNSSandbox{}, err
	}
	return sandbox, nil
}

func (a *DNSSandboxWithCreds) Reload() error {
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
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS additional_vars
		 FROM resources r
		 LEFT JOIN dns_account_configurations oc ON oc.name = resource_data->>'dns_account'
		 WHERE r.id = $1 AND r.resource_type = 'DNSSandbox'`,
		a.ID, a.Provider.VaultSecret,
	)

	var creds string
	var sandbox DNSSandboxWithCreds
	if err := row.Scan(
		&sandbox,
		&sandbox.ID,
		&sandbox.Name,
		&sandbox.Kind,
		&sandbox.CreatedAt,
		&sandbox.UpdatedAt,
		&sandbox.Status,
		&sandbox.CleanupCount,
		&creds,
		&sandbox.AdditionalVars,
	); err != nil {
		return err
	}
	// Add provider before copying
	sandbox.Provider = a.Provider
	// Copy sandbox into a
	*a = sandbox

	// Unmarshal creds into sandbox.Credentials
	if err := json.Unmarshal([]byte(creds), &a.Credentials); err != nil {
		return err
	}

	return nil
}
