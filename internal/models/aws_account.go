package models

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

var ErrAccountNotFound = errors.New("account not found")

type AwsAccount struct {
	Account
	Kind         string `json:"kind"` // "AwsSandbox"
	Name         string `json:"name"`
	Reservation  string `json:"reservation,omitempty"`
	AccountID    string `json:"account_id"`
	Zone         string `json:"zone"`
	HostedZoneID string `json:"hosted_zone_id"`

	ConanStatus       string    `json:"conan_status,omitempty"`
	ConanTimestamp    time.Time `json:"conan_timestamp,omitempty"`
	ConanHostname     string    `json:"conan_hostname,omitempty"`
	ConanCleanupCount int       `json:"conan_cleanup_count,omitempty"`
}

func (a *AwsAccount) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *AwsAccountWithCreds) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type AwsAccounts []AwsAccount

func (a *AwsAccounts) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type AwsAccountWithCreds struct {
	AwsAccount

	Credentials []any              `json:"credentials"`
	Provider    AwsAccountProvider `json:"-"`
}

type AwsIamKey struct {
	Kind               string `json:"kind"` // "aws_iam_key"
	Name               string `json:"name"`
	AwsAccessKeyID     string `json:"aws_access_key_id"`
	AwsSecretAccessKey string `json:"aws_secret_access_key"`
}

// AwsAccountProvider interface to interact with different databases:
// dynamodb and postgresql
type AwsAccountProvider interface {
	//Annotations(account AwsAccount) (map[string]string, error)
	Count() (int, error)
	CountAvailable(reservation string) (int, error)
	DecryptSecret(encrypted string) (string, error)
	Delete(name string) error
	FetchAll() ([]AwsAccount, error)
	FetchAllActiveByServiceUuid(serviceUuid string) ([]AwsAccount, error)
	FetchAllActiveByServiceUuidWithCreds(serviceUuid string) ([]AwsAccountWithCreds, error)
	FetchAllAvailable() ([]AwsAccount, error)
	FetchAllByReservation(reservation string) ([]AwsAccount, error)
	FetchAllByServiceUuid(serviceUuid string) ([]AwsAccount, error)
	FetchAllByServiceUuidWithCreds(serviceUuid string) ([]AwsAccountWithCreds, error)
	FetchAllSorted(by string) ([]AwsAccount, error)
	FetchAllToCleanup() ([]AwsAccount, error)
	FetchByName(name string) (AwsAccount, error)
	MarkForCleanup(name string) error
	MarkForCleanupByServiceUuid(serviceUuid string) error
	Request(service_uuid string, reservation string, count int, annotations Annotations) ([]AwsAccountWithCreds, error)
	Reserve(reservation string, count int) ([]AwsAccount, error)
	ScaleDownReservation(reservation string, count int) error
}

type Sortable interface {
	NameInt() int
	GetUpdatedAt() time.Time
}

func convertNameToInt(s string) int {
	var result strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if '0' <= b && b <= '9' {
			result.WriteByte(b)
		}
	}
	resultI, err := strconv.Atoi(result.String())
	if err != nil {
		log.Logger.Error("Convert name to int", "error", err)
		os.Exit(1)
	}
	return resultI
}

func (a AwsAccount) NameInt() int {
	return convertNameToInt(a.Name)
}

func (a AwsAccount) GetUpdatedAt() time.Time {
	return a.UpdatedAt
}

func Sort[T Sortable](accounts []T, by string) []T {
	sort.SliceStable(accounts, func(i, j int) bool {
		switch by {
		case "name":
			return accounts[i].NameInt() < accounts[j].NameInt()
		default:
			return accounts[i].GetUpdatedAt().After(accounts[j].GetUpdatedAt())
		}
	})

	return accounts
}

// Start method starts all the stopped instances in the account
func (a AwsAccount) Start(ctx context.Context, creds *ststypes.Credentials) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Logger.Error("Error loading config", "error", err)
		return err
	}

	sandboxCreds := credentials.StaticCredentialsProvider{
		Value: aws.Credentials{
			AccessKeyID:     *creds.AccessKeyId,
			SecretAccessKey: *creds.SecretAccessKey,
			SessionToken:    *creds.SessionToken,
		},
	}

	// Create new EC2 client
	ec2Client := ec2.NewFromConfig(
		cfg,
		func(o *ec2.Options) {
			o.Credentials = sandboxCreds
		},
	)
	// Describe all EC2 regions
	regions, err := ec2Client.DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})

	if err != nil {
		log.Logger.Error("Error describing regions", "account", a.Name, "error", err)
		return err
	}

	var errR error
	// For each region, get all running instances
	for _, region := range regions.Regions {
		log.Logger.Debug("Looping to start instances", "account", a.Name, "region", *region.RegionName)
		// Create new EC2 client
		ec2ClientRegional := ec2.NewFromConfig(
			cfg,
			func(o *ec2.Options) {
				o.Credentials = sandboxCreds
				o.Region = *region.RegionName
			},
		)

		// Describe all EC2 instances
		instances, err := ec2ClientRegional.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
			Filters: []ec2types.Filter{
				{
					Name:   aws.String("instance-state-name"),
					Values: []string{"stopped", "stopping"},
				},
			},
		})

		if err != nil {
			log.Logger.Error("Error describing instances", "account", a.Name, "error", err)
			errR = err
			continue
		}

		// Start all instances
		for _, reservation := range instances.Reservations {
			for _, instance := range reservation.Instances {
				_, err := ec2ClientRegional.StartInstances(context.TODO(), &ec2.StartInstancesInput{
					InstanceIds: []string{*instance.InstanceId},
				})

				if err != nil {
					log.Logger.Error("Error starting instance", "account", a.Name, "error", err)
					errR = err
					continue
				}
				log.Logger.Info("Start instance",
					"account", a.Name,
					"account_id", a.AccountID,
					"instance_id", *instance.InstanceId,
					"instance_type", instance.InstanceType,
					"region", *region.RegionName,
					"request_id", ctx.Value("RequestID"),
					"service_uuid", ctx.Value("ServiceUUID"),
				)
			}
		}
	}

	return errR
}

// Stop method stops all the running instances in the account
func (a AwsAccount) Stop(ctx context.Context, creds *ststypes.Credentials) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Logger.Error("Error loading config", "error", err)
		return err
	}

	sandboxCreds := credentials.StaticCredentialsProvider{
		Value: aws.Credentials{
			AccessKeyID:     *creds.AccessKeyId,
			SecretAccessKey: *creds.SecretAccessKey,
			SessionToken:    *creds.SessionToken,
		},
	}

	// Create new EC2 client
	ec2Client := ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Credentials = sandboxCreds })
	// Describe all EC2 regions
	regions, err := ec2Client.DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})

	if err != nil {
		log.Logger.Error("Error describing regions", "account", a.Name, "error", err)
		return err
	}

	var errR error
	// For each region, get all running instances
	for _, region := range regions.Regions {
		log.Logger.Debug("Looping to stop instances", "account", a.Name, "region", *region.RegionName)
		// Create new EC2 client
		ec2ClientRegional := ec2.NewFromConfig(
			cfg,
			func(o *ec2.Options) {
				o.Credentials = sandboxCreds
				o.Region = *region.RegionName
			},
		)

		// Describe all EC2 instances
		instances, err := ec2ClientRegional.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
			Filters: []ec2types.Filter{
				{
					Name:   aws.String("instance-state-name"),
					Values: []string{"running", "pending"},
				},
			},
		})

		if err != nil {
			log.Logger.Error("Error describing instances", "account", a.Name, "error", err)
			errR = err
			continue
		}

		// Start all instances
		for _, reservation := range instances.Reservations {
			for _, instance := range reservation.Instances {
				_, err := ec2ClientRegional.StopInstances(context.TODO(), &ec2.StopInstancesInput{
					InstanceIds: []string{*instance.InstanceId},
				})

				if err != nil {
					log.Logger.Error("Error stopping instance", "account", a.Name, "error", err)
					errR = err
					continue
				}
				log.Logger.Info("Stop instance",
					"account", a.Name,
					"account_id", a.AccountID,
					"instance_id", *instance.InstanceId,
					"instance_type", instance.InstanceType,
					"region", *region.RegionName,
					"request_id", ctx.Value("RequestID"),
					"service_uuid", ctx.Value("ServiceUUID"),
				)
			}
		}
	}

	return errR

}

type Instance struct {
	InstanceId   string `json:"instance_id,omitempty"`
	InstanceName string `json:"instance_name,omitempty"`
	InstanceType string `json:"instance_type,omitempty"`
	Region       string `json:"region,omitempty"`
	State        string `json:"state,omitempty"`
}

// Status type
type Status struct {
	AccountName string     `json:"account_name"`
	AccountKind string     `json:"account_kind"`
	Instances   []Instance `json:"instances"`
	UpdatedAt   time.Time  `json:"updated_at,omitempty"`
	Status      string     `json:"status,omitempty"`
}

func MakeStatus(job *LifecycleResourceJob) Status {
	var status Status

	status = job.Result
	status.AccountKind = job.ResourceType
	if status.AccountKind == "aws_account" {
		status.AccountKind = "AwsSandbox"
	}
	status.AccountName = job.ResourceName
	status.UpdatedAt = job.UpdatedAt
	status.Status = job.Status

	return status
}

// Status method returns the status of all the instances in the account
func (a AwsAccount) Status(ctx context.Context, creds *ststypes.Credentials, job *LifecycleResourceJob) (Status, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Logger.Error("Error loading config", "error", err)
		return Status{}, err
	}

	sandboxCreds := credentials.StaticCredentialsProvider{
		Value: aws.Credentials{
			AccessKeyID:     *creds.AccessKeyId,
			SecretAccessKey: *creds.SecretAccessKey,
			SessionToken:    *creds.SessionToken,
		},
	}

	// Create new EC2 client
	ec2Client := ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Credentials = sandboxCreds })
	// Describe all EC2 regions
	regions, err := ec2Client.DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})

	if err != nil {
		log.Logger.Error("Error describing regions", "account", a.Name, "error", err)
		return Status{}, err
	}

	var errR error
	var status Status
	instances := make([]Instance, 0)
	// For each region, get all running instances
	for _, region := range regions.Regions {
		log.Logger.Debug("Looping to get instances status", "account", a.Name, "region", *region.RegionName)
		// Create new EC2 client
		ec2ClientRegional := ec2.NewFromConfig(
			cfg,
			func(o *ec2.Options) {
				o.Credentials = sandboxCreds
				o.Region = *region.RegionName
			},
		)

		// Describe all EC2 instances
		ec2Instances, err := ec2ClientRegional.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})

		if err != nil {
			log.Logger.Error("Error describing instances", "account", a.Name, "error", err)
			errR = err
			continue
		}

		// Build instances
		for _, reservation := range ec2Instances.Reservations {
			for _, instance := range reservation.Instances {
				instances = append(instances, Instance{
					InstanceId:   *instance.InstanceId,
					InstanceType: string(instance.InstanceType),
					Region:       *region.RegionName,
					State:        string(instance.State.Name),
				})
			}
		}
	}

	status.Instances = instances
	status.AccountName = a.Name
	status.AccountKind = a.Kind

	// save status as json
	_, err = job.DbPool.Exec(
		context.TODO(),
		`UPDATE lifecycle_resource_jobs SET lifecycle_result = $1 WHERE id = $2`,
		status, job.ID,
	)
	if err != nil {
		log.Logger.Error("Error saving result", "error", err, "job", job)
		return status, err
	}

	return status, errR
}

func (a AwsAccount) GetLastStatus(dbpool *pgxpool.Pool) (*LifecycleResourceJob, error) {
	var id int
	err := dbpool.QueryRow(
		context.TODO(),
		`SELECT id FROM lifecycle_resource_jobs
         WHERE lifecycle_action = 'status' AND lifecycle_result IS NOT NULL
         AND lifecycle_result != '{}'
         AND resource_name = $1 AND resource_type = $2
         ORDER BY updated_at DESC LIMIT 1`,
		a.Name, a.Kind,
	).Scan(&id)

	if err != nil {
		return nil, err
	}

	job, err := GetLifecycleResourceJob(dbpool, id)

	if err != nil {
		return nil, err
	}

	return job, nil
}

func (a AwsAccount) GetReservation() string {
	return a.Reservation
}

func (a AwsAccount) CloseAccount() error {

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
	)
	if err != nil {
		log.Logger.Error("Error loading config", "error", err)
		return err
	}

	// Create a client
	// Use ASSUMEROLE_AWS_ACCESS_KEY_ID and ASSUMEROLE_AWS_SECRET_ACCESS_KEY for credentials
	svc := organizations.NewFromConfig(cfg, func(o *organizations.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider(
			os.Getenv("ASSUMEROLE_AWS_ACCESS_KEY_ID"),
			os.Getenv("ASSUMEROLE_AWS_SECRET_ACCESS_KEY"),
			"",
		)
	})

	// Get status of the account
	accountStatus, err := svc.DescribeAccount(context.TODO(), &organizations.DescribeAccountInput{
		AccountId: &a.AccountID,
	})
	if err != nil {
		// if string 'AccountNotFoundException' is in the error message, the account does not exist
		if strings.Contains(err.Error(), "AccountNotFoundException") {
			return nil
		}

		return err
	}

	switch accountStatus.Account.Status {
	case orgtypes.AccountStatusActive:
		// Close the account
		if _, err := svc.CloseAccount(context.TODO(), &organizations.CloseAccountInput{
			AccountId: &a.AccountID,
		}); err != nil {
			return err
		}
		return nil

	case orgtypes.AccountStatusSuspended, orgtypes.AccountStatusPendingClosure:
		log.Logger.Info(
			"Account already closed",
			"status", accountStatus.Account.Status,
			"account", a.Name,
			"account_id", a.AccountID)
		return nil
	}
	return nil
}

func (a *AwsAccountWithCreds) Delete() error {
	return a.Provider.MarkForCleanup(a.Name)
}
