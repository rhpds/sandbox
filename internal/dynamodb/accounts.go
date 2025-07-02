package dynamodb

import (
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
	vault "github.com/sosedoff/ansible-vault-go"
)

func parseNameInt(s string) int {
	var result strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if '0' <= b && b <= '9' {
			result.WriteByte(b)
		}
	}
	resultI, err := strconv.Atoi(result.String())
	if err != nil {
		log.Err.Fatal(err)
	}
	return resultI
}

// Internal Type to represent the dynamodb table
type AwsAccountDynamoDB struct {
	Name string `json:"name"`
	// NameInt: Internal plumbing to easily sort Sandboxes
	NameInt            int
	Available          bool    `json:"available"`
	Reservation        string  `json:"reservation,omitempty"`
	Guid               string  `json:"guid"`
	ServiceUUID        string  `json:"service_uuid"`
	Envtype            string  `json:"envtype"`
	AccountID          string  `json:"account_id"`
	Owner              string  `json:"owner"`
	OwnerEmail         string  `json:"owner_email"`
	Zone               string  `json:"zone"`
	HostedZoneID       string  `json:"hosted_zone_id"`
	UpdateTime         float64 `json:"aws:rep:updatetime"`
	Comment            string  `json:"comment"`
	AwsAccessKeyID     string  `json:"aws_access_key_id"`
	AwsSecretAccessKey string  `json:"aws_secret_access_key"`
	// Conan
	ToCleanup         bool              `json:"to_cleanup"`
	ConanStatus       string            `json:"conan_status"`
	ConanTimestamp    string            `json:"conan_timestamp"`
	ConanHostname     string            `json:"conan_hostname"`
	ConanCleanupCount int               `json:"conan_cleanup_count"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

// buildAccounts returns the list of accounts from dynamodb scan output
func buildAccounts(r *dynamodb.ScanOutput) []AwsAccountDynamoDB {
	accounts := []AwsAccountDynamoDB{}

	for _, sandbox := range r.Items {
		item := AwsAccountDynamoDB{}
		err := dynamodbattribute.UnmarshalMap(sandbox, &item)
		if err != nil {
			log.Logger.Error("Got error unmarshalling:", "sandbox", sandbox, "error", err)
			continue
		}

		item.NameInt = parseNameInt(item.Name)

		accounts = append(accounts, item)
	}

	return accounts
}

type AwsAccountDynamoDBProvider struct {
	Svc         *dynamodb.DynamoDB
	VaultSecret string
}

func NewAwsAccountDynamoDBProvider() *AwsAccountDynamoDBProvider {
	return &AwsAccountDynamoDBProvider{
		Svc: dynamodb.New(session.Must(session.NewSession())),
	}
}

func NewAwsAccountDynamoDBProviderWithSecret(vaultSecret string) *AwsAccountDynamoDBProvider {
	return &AwsAccountDynamoDBProvider{
		Svc:         dynamodb.New(session.Must(session.NewSession())),
		VaultSecret: vaultSecret,
	}
}

// makeAccount creates new models.AwsAccount from AwsAccountDynamoDB
func makeAccount(account AwsAccountDynamoDB) models.AwsAccount {
	a := models.AwsAccount{
		Name:              account.Name,
		Kind:              "AwsSandbox",
		Reservation:       account.Reservation,
		AccountID:         account.AccountID,
		Zone:              account.Zone,
		HostedZoneID:      account.HostedZoneID,
		ConanStatus:       account.ConanStatus,
		ConanHostname:     account.ConanHostname,
		ConanCleanupCount: account.ConanCleanupCount,
	}
	if conanTime, err := time.Parse(time.RFC3339, account.ConanTimestamp); err != nil {
		a.ConanTimestamp = conanTime
	}

	a.ServiceUuid = account.ServiceUUID
	a.ToCleanup = account.ToCleanup
	a.Available = account.Available
	a.ServiceUuid = account.ServiceUUID

	ti, err := strconv.ParseInt(strconv.FormatFloat(account.UpdateTime, 'f', 0, 64), 10, 64)
	if err != nil {
		log.Logger.Error("Got error parsing update time:", "error", err)
	}

	a.UpdatedAt = time.Unix(ti, 0)

	a.Annotations = map[string]string{}
	// Restore original Annotations
	if account.Annotations != nil {
		for k, v := range account.Annotations {
			a.Annotations[k] = v
		}
	}

	if account.Guid != "" {
		a.Annotations["guid"] = account.Guid
	}
	if account.Owner != "" {
		a.Annotations["owner"] = account.Owner
	}
	if account.OwnerEmail != "" {
		a.Annotations["owner_email"] = account.OwnerEmail
	}
	if account.Comment != "" {
		a.Annotations["comment"] = account.Comment
	}
	if account.Envtype != "" {
		a.Annotations["env_type"] = account.Envtype
	}

	return a
}

// makeAccounts creates new []models.AwsAccount from []AwsAccountDynamoDB
func makeAccounts(accounts []AwsAccountDynamoDB) []models.AwsAccount {
	r := []models.AwsAccount{}
	for _, account := range accounts {
		r = append(r, makeAccount(account))
	}

	return r
}

// makeAccountWithCreds creates new models.AwsAccountWithCreds from AwsAccountDynamoDB
func (provider *AwsAccountDynamoDBProvider) makeAccountWithCreds(account AwsAccountDynamoDB) models.AwsAccountWithCreds {

	a := makeAccount(account)

	result := models.AwsAccountWithCreds{
		AwsAccount: a,
		Provider:   provider,
	}

	decrypted, err := provider.DecryptSecret(account.AwsSecretAccessKey)
	if err != nil {
		decrypted = account.AwsSecretAccessKey
	}

	iamKey := models.AwsIamKey{
		Kind:               "aws_iam_key",
		Name:               "admin-key",
		AwsAccessKeyID:     account.AwsAccessKeyID,
		AwsSecretAccessKey: decrypted,
	}

	// For now, an account only has one credential: an IAM key
	result.Credentials = []any{iamKey}

	return result
}

// makeAccountsWithCreds creates new []models.AwsAccountWithCreds from []AwsAccountDynamoDB
func (provider *AwsAccountDynamoDBProvider) makeAccountsWithCreds(accounts []AwsAccountDynamoDB) []models.AwsAccountWithCreds {
	r := []models.AwsAccountWithCreds{}
	for _, account := range accounts {
		r = append(r, provider.makeAccountWithCreds(account))
	}

	return r
}

func GetAccount(svc *dynamodb.DynamoDB, name string) (AwsAccountDynamoDB, error) {
	sandbox := AwsAccountDynamoDB{Name: name}

	// Build the Get query input parameters
	input := &dynamodb.GetItemInput{
		TableName: aws.String(os.Getenv("dynamodb_table")),
		Key: map[string]*dynamodb.AttributeValue{
			"name": {
				S: aws.String(name),
			},
		},
	}

	// Get the item from the table
	output, errget := svc.GetItem(input)

	if errget != nil {
		if aerr, ok := errget.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeProvisionedThroughputExceededException:
				log.Err.Println(dynamodb.ErrCodeProvisionedThroughputExceededException, aerr.Error())
			case dynamodb.ErrCodeResourceNotFoundException:
				log.Err.Println(dynamodb.ErrCodeResourceNotFoundException, aerr.Error())
			case dynamodb.ErrCodeRequestLimitExceeded:
				log.Err.Println(dynamodb.ErrCodeRequestLimitExceeded, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				log.Err.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				log.Err.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Logger.Error(errget.Error())
		}

		log.Logger.Error("error", "error", errget)
		return AwsAccountDynamoDB{}, errget
	}

	if len(output.Item) == 0 {
		return AwsAccountDynamoDB{}, models.ErrAccountNotFound
	}

	if err := dynamodbattribute.UnmarshalMap(output.Item, &sandbox); err != nil {
		log.Logger.Error("Unmarshalling dynamodb item", "error", err)
		return AwsAccountDynamoDB{}, err
	}

	return sandbox, nil
}

func GetAccounts(svc *dynamodb.DynamoDB, filter expression.ConditionBuilder, batchSize int) ([]AwsAccountDynamoDB, error) {
	accounts := []AwsAccountDynamoDB{}

	builder := expression.NewBuilder().WithFilter(filter)

	expr, err := builder.Build()

	if err != nil {
		log.Logger.Error("error building expression", "error", err)
		return accounts, err
	}

	input := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		TableName:                 aws.String(os.Getenv("dynamodb_table")),
		ProjectionExpression:      expr.Projection(),
		FilterExpression:          expr.Filter(),
	}

	errscan := svc.ScanPages(input,
		func(page *dynamodb.ScanOutput, lastPage bool) bool {
			accounts = append(accounts, buildAccounts(page)...)
			if batchSize > 0 && len(accounts) >= batchSize {
				accounts = accounts[:batchSize]
				return false
			}

			return true
		})

	//result, err := svc.Scan(input)
	if errscan != nil {
		if aerr, ok := errscan.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeProvisionedThroughputExceededException:
				log.Err.Println(dynamodb.ErrCodeProvisionedThroughputExceededException, aerr.Error())
			case dynamodb.ErrCodeResourceNotFoundException:
				log.Err.Println(dynamodb.ErrCodeResourceNotFoundException, aerr.Error())
			case dynamodb.ErrCodeRequestLimitExceeded:
				log.Err.Println(dynamodb.ErrCodeRequestLimitExceeded, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				log.Err.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				log.Err.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Err.Println(errscan.Error())
		}
		return []AwsAccountDynamoDB{}, errscan
	}

	return accounts, nil
}

func (a *AwsAccountDynamoDBProvider) FetchByName(name string) (models.AwsAccount, error) {
	account, err := GetAccount(a.Svc, name)
	if err != nil {
		return models.AwsAccount{}, err
	}
	return makeAccount(account), nil
}

// FetchAll returns the list of all accounts from dynamodb
func (a *AwsAccountDynamoDBProvider) FetchAll() ([]models.AwsAccount, error) {
	filter := expression.Name("name").AttributeExists()
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccount{}, err
	}
	return makeAccounts(accounts), nil
}

// FetchAllAvailable returns the list of available accounts from dynamodb
func (a *AwsAccountDynamoDBProvider) FetchAllAvailable() ([]models.AwsAccount, error) {
	filter := expression.Name("name").AttributeExists().
		And(expression.Name("available").Equal(expression.Value(true)))
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccount{}, err
	}
	return makeAccounts(accounts), nil
}

// FetchAllByServiceUuid returns the list of accounts from dynamodb for a specific service uuid
func (a *AwsAccountDynamoDBProvider) FetchAllByServiceUuid(serviceUuid string) ([]models.AwsAccount, error) {
	filter := expression.Name("service_uuid").Equal(expression.Value(serviceUuid))
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccount{}, err
	}
	return makeAccounts(accounts), nil
}

// FetchAllActiveByServiceUuid returns the list of accounts from dynamodb for a specific service uuid that are not to cleanup
func (a *AwsAccountDynamoDBProvider) FetchAllActiveByServiceUuid(serviceUuid string) ([]models.AwsAccount, error) {
	filter := expression.Name("service_uuid").Equal(expression.Value(serviceUuid)).
		And(expression.Name("to_cleanup").AttributeNotExists().
			Or(expression.Name("to_cleanup").Equal(expression.Value(false))))
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccount{}, err
	}
	return makeAccounts(accounts), nil
}

// FetchAllByServiceUuidWithCreds returns the list of accounts from dynamodb for a specific service uuid
func (a *AwsAccountDynamoDBProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]models.AwsAccountWithCreds, error) {
	filter := expression.Name("service_uuid").Equal(expression.Value(serviceUuid))
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccountWithCreds{}, err
	}
	return a.makeAccountsWithCreds(accounts), nil
}

// FetchAllActiveByServiceUuidWithCreds returns the list of accounts from dynamodb for a specific service uuid
func (a *AwsAccountDynamoDBProvider) FetchAllActiveByServiceUuidWithCreds(serviceUuid string) ([]models.AwsAccountWithCreds, error) {
	filter := expression.Name("service_uuid").Equal(expression.Value(serviceUuid)).
		And(expression.Name("to_cleanup").AttributeNotExists().
			Or(expression.Name("to_cleanup").Equal(expression.Value(false))))
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccountWithCreds{}, err
	}
	return a.makeAccountsWithCreds(accounts), nil
}

// FetchAllToCleanup returns the list of accounts from dynamodb
func (a *AwsAccountDynamoDBProvider) FetchAllToCleanup() ([]models.AwsAccount, error) {
	filter := expression.Name("to_cleanup").Equal(expression.Value(true))
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccount{}, err
	}
	return makeAccounts(accounts), nil
}

// FetchAllSorted
func (a *AwsAccountDynamoDBProvider) FetchAllSorted(by string) ([]models.AwsAccount, error) {
	filter := expression.Name("name").AttributeExists()
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccount{}, err
	}

	sort.SliceStable(accounts, func(i, j int) bool {
		switch by {
		case "name":
			return accounts[i].NameInt < accounts[j].NameInt
		default:
			return accounts[i].UpdateTime > accounts[j].UpdateTime
		}
	})

	return makeAccounts(accounts), nil
}

func (a *AwsAccountDynamoDBProvider) GetCandidates(reservation string, count int) ([]models.AwsAccount, error) {
	if count <= 0 {
		return []models.AwsAccount{}, errors.New("count must be > 0")
	}

	// Get first available accounts older than 24h
	// older than 24h is to facilitate cost reporting.
	yesterday := time.Now().Add(-24 * time.Hour).Unix()

	filter := expression.Name("available").Equal(expression.Value(true)).
		And(expression.Name("aws:rep:updatetime").LessThan(expression.Value(yesterday))).
		And(expression.Name("aws_access_key_id").AttributeExists()).
		And(expression.Name("aws_secret_access_key").AttributeExists()).
		And(expression.Name("hosted_zone_id").AttributeExists()).
		And(expression.Name("account_id").AttributeExists())

	if reservation != "" {
		filter = filter.And(expression.Name("reservation").Equal(expression.Value(reservation)))
	} else {
		filter = filter.And(expression.Name("reservation").AttributeNotExists().
			Or(expression.Name("reservation").Equal(expression.Value(""))))
	}

	// get 10 spare accounts in case of concurrency doublebooking
	accounts, err := GetAccounts(a.Svc, filter, count+10)

	if err != nil {
		log.Logger.Error("Error getting accounts", "error", err)
		return []models.AwsAccount{}, err
	}

	if len(accounts) < count {
		// Retry without the 24h filter
		filter := expression.Name("available").Equal(expression.Value(true)).
			And(expression.Name("aws_access_key_id").AttributeExists()).
			And(expression.Name("aws_secret_access_key").AttributeExists()).
			And(expression.Name("hosted_zone_id").AttributeExists()).
			And(expression.Name("account_id").AttributeExists())

		if reservation != "" {
			filter = filter.And(expression.Name("reservation").Equal(expression.Value(reservation)))
		} else {
			filter = filter.And(expression.Name("reservation").AttributeNotExists().
				Or(expression.Name("reservation").Equal(expression.Value(""))))
		}

		accounts, err = GetAccounts(a.Svc, filter, count+10)

		if err != nil {
			log.Logger.Error("Error getting accounts", "error", err)
			return []models.AwsAccount{}, err
		}

		if len(accounts) < count {
			return []models.AwsAccount{}, models.ErrNoEnoughAccountsAvailable
		}
	}

	r := make([]models.AwsAccount, 0, count)
	for _, account := range accounts {
		r = append(r, makeAccount(account))
	}

	return r, nil
}

// Request reserve accounts for a service
func (a *AwsAccountDynamoDBProvider) Request(service_uuid string, reservation string, count int, annotations models.Annotations) ([]models.AwsAccountWithCreds, error) {
	accounts, err := a.GetCandidates(reservation, count)
	if err != nil {
		return []models.AwsAccountWithCreds{}, err
	}

	bookedAccounts := []models.AwsAccountWithCreds{}

	annotationsAttr, err := dynamodbattribute.MarshalMap(annotations)
	if err != nil {
		log.Logger.Error("Can't marshal annotations")

		return []models.AwsAccountWithCreds{}, err
	}
	for _, sandbox := range accounts {
		// Update the account
		output, err := a.Svc.UpdateItem(&dynamodb.UpdateItemInput{
			TableName: aws.String(os.Getenv("dynamodb_table")),
			Key: map[string]*dynamodb.AttributeValue{
				"name": {
					S: aws.String(sandbox.Name),
				},
			},
			UpdateExpression: aws.String(
				`SET available = :av,
				guid = :gu,
				envtype = :en,
				service_uuid = :uu,
				#o = :ow,
 				owner_email = :email,
 				#c = :co,
				annotations = :annotations
				`,
			),
			ExpressionAttributeNames: map[string]*string{
				"#o": aws.String("owner"),
				"#c": aws.String("comment"),
			},
			ConditionExpression: aws.String("available = :currval"),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":av": {
					BOOL: aws.Bool(false),
				},
				":gu": {
					S: aws.String(annotations["guid"]),
				},
				":en": {
					S: aws.String(annotations["env_type"]),
				},
				":uu": {
					S: aws.String(service_uuid),
				},
				":currval": {
					BOOL: aws.Bool(true),
				},
				":ow": {
					S: aws.String(annotations["owner"]),
				},
				":email": {
					S: aws.String(annotations["owner_email"]),
				},
				":co": {
					S: aws.String(annotations["comment"]),
				},
				":annotations": {
					M: annotationsAttr,
				},
			},
			ReturnValues: aws.String("ALL_NEW"),
		})
		if err != nil {
			log.Logger.Error("error booking the sandbox", "sandbox", sandbox.Name, "error", err)
			continue
		}

		var booked AwsAccountDynamoDB
		if err := dynamodbattribute.UnmarshalMap(output.Attributes, &booked); err != nil {
			log.Logger.Error("error unmarshaling", "error", err)
			return []models.AwsAccountWithCreds{}, err
		}
		booked.AwsSecretAccessKey, err = a.DecryptSecret(booked.AwsSecretAccessKey)
		if err != nil {
			log.Logger.Error("error decrypting secret", "error", err)
			return []models.AwsAccountWithCreds{}, err
		}
		booked.AwsSecretAccessKey = strings.Trim(booked.AwsSecretAccessKey, "\n\r\t ")
		bookedFinal := a.makeAccountWithCreds(booked)
		bookedFinal.Annotations = bookedFinal.Annotations.Merge(annotations)
		bookedAccounts = append(bookedAccounts, bookedFinal)
		count = count - 1
		if count == 0 {
			break
		}
	}

	if count != 0 {
		log.Logger.Error("error booking the sandboxes")
		return []models.AwsAccountWithCreds{}, errors.New("error booking the sandboxes")
	}

	return bookedAccounts, nil
}

// Reserve reserve accounts for a reservation
// It takes the number of account to reserve.
// The function iterates over available accounts and update the 'reservation' column
func (a *AwsAccountDynamoDBProvider) Reserve(reservation string, count int) ([]models.AwsAccount, error) {
	maxRetries := 5

	result, err := a.FetchAllByReservation(reservation)
	if err != nil {
		return []models.AwsAccount{}, err
	}

	// If reservation is already bigger than target, return
	if len(result) >= count {
		return result, nil
	}

	for i := 0; i < maxRetries; i++ {
		todo := count - len(result)

		if todo <= 0 {
			return result, nil
		}

		accounts, err := a.reserveInner(reservation, todo)

		if err != nil {
			return []models.AwsAccount{}, err
		}

		result = append(result, accounts...)

		if len(result) >= count {
			return result, nil
		}
	}

	return []models.AwsAccount{}, errors.New("error reserving the sandboxes")
}

// reserveInner is just an helper function for the Reserve function
// to keep indentation under control.
// It takes the number of account to reserve.
// The function iterates over available accounts and update the 'reservation' column
func (a *AwsAccountDynamoDBProvider) reserveInner(reservation string, count int) ([]models.AwsAccount, error) {
	if count <= 0 {
		return []models.AwsAccount{}, errors.New("count must be > 0")
	}

	filter := expression.Name("available").Equal(expression.Value(true)).
		And(expression.Name("reservation").AttributeNotExists().
			Or(expression.Name("reservation").Equal(expression.Value("")))).
		And(expression.Name("aws_access_key_id").AttributeExists()).
		And(expression.Name("aws_secret_access_key").AttributeExists()).
		And(expression.Name("hosted_zone_id").AttributeExists()).
		And(expression.Name("account_id").AttributeExists())

	accounts, err := GetAccounts(a.Svc, filter, count)

	if err != nil {
		log.Logger.Error("Error getting accounts", "error", err)
		return []models.AwsAccount{}, err
	}

	if len(accounts) < count {
		return []models.AwsAccount{}, models.ErrNoEnoughAccountsAvailable
	}

	reserved := []models.AwsAccount{}
	for _, sandbox := range accounts {
		// Update the account
		output, err := a.Svc.UpdateItem(&dynamodb.UpdateItemInput{
			TableName: aws.String(os.Getenv("dynamodb_table")),
			Key: map[string]*dynamodb.AttributeValue{
				"name": {
					S: aws.String(sandbox.Name),
				},
			},
			UpdateExpression: aws.String(
				`SET reservation = :rv`,
			),
			ConditionExpression: aws.String(
				`available = :t
                 and (attribute_not_exists(reservation) or reservation = :empty)
                 and (attribute_not_exists(to_cleanup) or to_cleanup = :f)`,
			),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":rv": {
					S: aws.String(reservation),
				},
				":f": {
					BOOL: aws.Bool(false),
				},
				":empty": {
					S: aws.String(""),
				},
				":t": {
					BOOL: aws.Bool(true),
				},
			},
			ReturnValues: aws.String("ALL_NEW"),
		})
		if err != nil {
			log.Logger.Error("error reserving sandbox",
				"sandbox", sandbox.Name,
				"reservation", reservation,
				"error", err)
			continue
		}

		var newReserved AwsAccountDynamoDB
		if err := dynamodbattribute.UnmarshalMap(output.Attributes, &newReserved); err != nil {
			log.Logger.Error("error unmarshaling",
				"error", err,
				"sandbox", sandbox.Name,
			)
			continue
		}
		reserved = append(reserved, makeAccount(newReserved))
		log.Logger.Info(
			"Sandbox reserved",
			"reservation", reservation,
			"sandbox", sandbox.Name)
		count = count - 1
		if count == 0 {
			break
		}
	}

	return reserved, nil
}

// ScaleDownReservation scale down a reservation
// It removes some of the accounts from the reservation
func (a *AwsAccountDynamoDBProvider) ScaleDownReservation(reservation string, count int) error {
	accounts, err := a.FetchAllByReservation(reservation)

	if err != nil {
		return err
	}

	if len(accounts) < count {
		// You can't scale down something that is already smaller than the target
		return nil
	}

	// Remove reservation until target is reached.

	done := 0
	for _, account := range models.Sort(accounts, "name") {
		if len(accounts)-done <= count {
			break
		}
		if err := a.RemoveReservation(account.Name); err != nil {
			return err
		}
		log.Logger.Info("Reservation removed",
			"reservation", reservation,
			"kind", "AwsSandbox",
			"name", account.Name)
		done = done + 1
	}

	if len(accounts)-done > count {
		return errors.New("error scaling down the reservation")
	}

	return nil
}

// RenameReservation rename a reservation
// It renames all the accounts from the old reservation to the new reservation
func (a *AwsAccountDynamoDBProvider) RenameReservation(oldReservation string, newReservation string) error {
	accounts, err := a.FetchAllByReservation(oldReservation)

	if err != nil {
		return err
	}

	for _, account := range accounts {
		_, err := a.Svc.UpdateItem(&dynamodb.UpdateItemInput{
			TableName: aws.String(os.Getenv("dynamodb_table")),
			Key: map[string]*dynamodb.AttributeValue{
				"name": {
					S: aws.String(account.Name),
				},
			},
			UpdateExpression: aws.String("SET reservation = :nr"),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":nr": {
					S: aws.String(newReservation),
				},
			},
		})
		if err != nil {
			log.Logger.Error("error renaming the reservation",
				"oldReservation", oldReservation,
				"newReservation", newReservation,
				"kind", "AwsSandbox",
				"name", account.Name,
				"error", err,
			)
			return err
		}

		log.Logger.Info("Reservation renamed for account",
			"name", account.Name,
			"oldReservation", oldReservation,
			"newReservation", newReservation,
			"kind", "AwsSandbox",
		)
	}

	return nil
}

func (a *AwsAccountDynamoDBProvider) MarkForCleanup(name string) error {
	_, err := a.Svc.UpdateItem(&dynamodb.UpdateItemInput{
		TableName: aws.String(os.Getenv("dynamodb_table")),
		Key: map[string]*dynamodb.AttributeValue{
			"name": {
				S: aws.String(name),
			},
		},
		UpdateExpression: aws.String("SET to_cleanup = :tc"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":tc": {
				BOOL: aws.Bool(true),
			},
		},
	})
	if err != nil {
		log.Logger.Error("error marking the sandbox for cleanup", "name", name, "error", err)
		return err
	}
	return nil
}

func (a *AwsAccountDynamoDBProvider) MarkForCleanupByServiceUuid(serviceUuid string) error {

	accounts, err := a.FetchAllByServiceUuid(serviceUuid)

	if err != nil {
		return err
	}

	for _, account := range accounts {

		_, err := a.Svc.UpdateItem(&dynamodb.UpdateItemInput{
			TableName: aws.String(os.Getenv("dynamodb_table")),
			Key: map[string]*dynamodb.AttributeValue{
				"name": {
					S: aws.String(account.Name),
				},
			},
			UpdateExpression: aws.String("SET to_cleanup = :tc"),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":tc": {
					BOOL: aws.Bool(true),
				},
			},
		})
		if err != nil {
			log.Logger.Error("error marking the sandbox for cleanup", "ServiceUuid", serviceUuid, "error", err)
			return err
		}

	}
	return nil
}

func (a *AwsAccountDynamoDBProvider) CountReservationAvailable(reservation string) (int, error) {
	var filter expression.ConditionBuilder

	if reservation == "" {
		filter = expression.Name("name").AttributeExists().
			And(expression.Name("reservation").AttributeNotExists().
				Or(expression.Name("reservation").Equal(expression.Value("")))).
			And(expression.Name("available").Equal(expression.Value(true))).
			And(expression.Name("to_cleanup").AttributeNotExists().
				Or(expression.Name("to_cleanup").Equal(expression.Value(false))))

	} else {
		filter = expression.Name("name").AttributeExists().
			And(expression.Name("reservation").AttributeExists()).
			And(expression.Name("reservation").Equal(expression.Value(reservation))).
			And(expression.Name("available").Equal(expression.Value(true))).
			And(expression.Name("to_cleanup").AttributeNotExists().
				Or(expression.Name("to_cleanup").Equal(expression.Value(false))))

	}
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return 0, err
	}
	return len(accounts), nil
}

func (a *AwsAccountDynamoDBProvider) CountAll() (int, error) {
	filter := expression.Name("name").AttributeExists()
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return 0, err
	}
	return len(accounts), nil
}

func (a *AwsAccountDynamoDBProvider) CountReservation(reservation string) (int, error) {
	var filter expression.ConditionBuilder

	if reservation == "" {
		filter = expression.Name("name").AttributeExists().
			And(expression.Name("reservation").AttributeNotExists().
				Or(expression.Name("reservation").Equal(expression.Value(""))))

	} else {
		filter = expression.Name("name").AttributeExists().
			And(expression.Name("reservation").AttributeExists()).
			And(expression.Name("reservation").Equal(expression.Value(reservation)))

	}
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return 0, err
	}
	return len(accounts), nil
}

func (a *AwsAccountDynamoDBProvider) DecryptSecret(encrypted string) (string, error) {
	str, err := vault.Decrypt(encrypted, a.VaultSecret)
	if err != nil {
		return "", err
	}
	str = strings.Trim(string(str), "\r\n\t ")
	return str, nil
}

// GetAccountsByReservation returns the list of accounts from dynamodb for a specific reservation
func (a *AwsAccountDynamoDBProvider) FetchAllByReservation(reservation string) ([]models.AwsAccount, error) {
	filter := expression.Name("reservation").Equal(expression.Value(reservation))
	accounts, err := GetAccounts(a.Svc, filter, -1)
	if err != nil {
		return []models.AwsAccount{}, err
	}
	return makeAccounts(accounts), nil
}

// RemoveReservation remove an account from a reservation
func (a *AwsAccountDynamoDBProvider) RemoveReservation(name string) error {
	_, err := a.Svc.UpdateItem(&dynamodb.UpdateItemInput{
		TableName: aws.String(os.Getenv("dynamodb_table")),
		Key: map[string]*dynamodb.AttributeValue{
			"name": {
				S: aws.String(name),
			},
		},
		UpdateExpression: aws.String("REMOVE reservation"),
	})
	if err != nil {
		log.Logger.Error("error removing the reservation", "name", name, "error", err)
		return err
	}

	return nil
}

// Delete deletes an account from dynamodb
func (a *AwsAccountDynamoDBProvider) Delete(name string) error {
	// Delete the entry from the DynamoDB table
	_, err := a.Svc.DeleteItem(&dynamodb.DeleteItemInput{
		TableName: aws.String(os.Getenv("dynamodb_table")),
		Key: map[string]*dynamodb.AttributeValue{
			"name": {
				S: aws.String(name),
			},
		},
	})

	if err != nil {
		log.Logger.Error("error deleting the sandbox", "name", name, "error", err)
		return err
	}

	return nil
}
