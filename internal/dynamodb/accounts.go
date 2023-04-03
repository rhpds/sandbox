package dynamodb

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
	"golang.org/x/exp/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrAccountNotFound = errors.New("account not found")

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
	ToCleanup      bool   `json:"to_cleanup"`
	ConanStatus    string `json:"conan_status"`
	ConanTimestamp string `json:"conan_timestamp"`
	ConanHostname  string `json:"conan_hostname"`
}

// buildAccounts returns the list of accounts from dynamodb scan output
func buildAccounts(r *dynamodb.ScanOutput) []AwsAccountDynamoDB {
	accounts := []AwsAccountDynamoDB{}

	for _, sandbox := range r.Items {
		item := AwsAccountDynamoDB{}
		err := dynamodbattribute.UnmarshalMap(sandbox, &item)
		if err != nil {
			log.Logger.Error("Got error unmarshalling:", err)
			os.Exit(1)
		}

		item.NameInt = parseNameInt(item.Name)

		accounts = append(accounts, item)
	}

	return accounts
}

type AwsAccountDynamoDBProvider struct {
	Svc *dynamodb.DynamoDB
}

func NewAwsAccountDynamoDBProvider() *AwsAccountDynamoDBProvider {
	return &AwsAccountDynamoDBProvider{
		Svc: dynamodb.New(session.Must(session.NewSession())),
	}
}

// makeAccount creates new models.AwsAccount from AwsAccountDynamoDB
func makeAccount(account AwsAccountDynamoDB) models.AwsAccount {
	a := models.AwsAccount{
		Name:          account.Name,
		AccountID:     account.AccountID,
		Zone:          account.Zone,
		HostedZoneID:  account.HostedZoneID,
		ConanStatus:   account.ConanStatus,
		ConanHostname: account.ConanHostname,
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
		log.Logger.Error("Got error parsing update time:", err)
	}

	a.UpdatedAt = time.Unix(ti, 0)

	// Rest of the fields are annotations
	annotations := map[string]string{}

	if account.Guid != "" {
		annotations["guid"] = account.Guid
	}
	if account.Owner != "" {
		annotations["owner"] = account.Owner
	}
	if account.OwnerEmail != "" {
		annotations["owner_email"] = account.OwnerEmail
	}
	if account.Comment != "" {
		annotations["comment"] = account.Comment
	}
	if account.Envtype != "" {
		annotations["env_type"] = account.Envtype
	}

	a.Resource.Annotations = annotations

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

		log.Logger.Error("errget", errget)
		return AwsAccountDynamoDB{}, errget
	}

	if len(output.Item) == 0 {
		return AwsAccountDynamoDB{}, ErrAccountNotFound
	}

	if err := dynamodbattribute.UnmarshalMap(output.Item, &sandbox); err != nil {
		log.Logger.Error("Unmarshalling", err)
		return AwsAccountDynamoDB{}, err
	}
	log.Logger.Info("GetItem succeeded", slog.String("sandbox", sandbox.Name))

	return sandbox, nil
}

func GetAccounts(svc *dynamodb.DynamoDB, filters []expression.ConditionBuilder) ([]AwsAccountDynamoDB, error) {
	accounts := []AwsAccountDynamoDB{}

	// Build dynamod query
	proj := expression.NamesList(
		expression.Name("name"),
		expression.Name("available"),
		expression.Name("to_cleanup"),
		expression.Name("guid"),
		expression.Name("service_uuid"),
		expression.Name("envtype"),
		expression.Name("owner"),
		expression.Name("zone"),
		expression.Name("hosted_zone_id"),
		expression.Name("account_id"),
		expression.Name("comment"),
		expression.Name("owner_email"),
		expression.Name("aws:rep:updatetime"),
		expression.Name("aws_access_key_id"),
		expression.Name("aws_secret_access_key"),
		expression.Name("conan_status"),
		expression.Name("conan_timestamp"),
		expression.Name("conan_hostname"),
	)

	builder := expression.NewBuilder()

	for _, filter := range filters {
		builder = builder.WithFilter(filter)
	}

	expr, err := builder.WithProjection(proj).Build()

	if err != nil {
		log.Err.Println("Got error building expression:")
		log.Err.Println(err.Error())
		os.Exit(1)
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

// GetAccounts returns the list of accounts from dynamodb
func (a *AwsAccountDynamoDBProvider) FetchAll() ([]models.AwsAccount, error) {
	filters := []expression.ConditionBuilder{}
	accounts, err := GetAccounts(a.Svc, filters)
	if err != nil {
		return []models.AwsAccount{}, err
	}
	return makeAccounts(accounts), nil
}

// GetAccountsToCleanup returns the list of accounts from dynamodb
func (a *AwsAccountDynamoDBProvider) FetchAllToCleanup() ([]models.AwsAccount, error) {
	filters := []expression.ConditionBuilder{
		expression.Name("to_cleanup").Equal(expression.Value(true)),
	}
	accounts, err := GetAccounts(a.Svc, filters)
	if err != nil {
		return []models.AwsAccount{}, err
	}
	return makeAccounts(accounts), nil
}

// FetchAllSorted
func (a *AwsAccountDynamoDBProvider) FetchAllSorted(by string) ([]models.AwsAccount, error) {
	filters := []expression.ConditionBuilder{}
	accounts, err := GetAccounts(a.Svc, filters)
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
