package dynamodb

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/rhpds/sandbox/internal/models"
	"github.com/rhpds/sandbox/internal/log"
	"golang.org/x/exp/slog"
	"os"
	"strconv"
	"strings"
	"errors"
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
	Name               string  `json:"name"`
	// NameInt: Internal plumbing to easily sort Sandboxes
	NameInt			   int
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
	ToCleanup          bool    `json:"to_cleanup"`
	ConanStatus        string  `json:"conan_status"`
	ConanTimestamp     string  `json:"conan_timestamp"`
	ConanHostname      string  `json:"conan_hostname"`
}

// BuildAccounts returns the list of accounts from dynamodb scan output
func BuildAccounts(r *dynamodb.ScanOutput) []models.AwsAccount {
	accounts := []models.AwsAccount{}

	for _, sandbox := range r.Items {
		item := models.AwsAccount{}
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



type AwsAccountDynamoDBRepository struct {
	Svc *dynamodb.DynamoDB
}

func NewAwsAccountDynamoDBRepository() *AwsAccountDynamoDBRepository {
	return &AwsAccountDynamoDBRepository{
		Svc: dynamodb.New(session.Must(session.NewSession())),
	}
}

func (a *AwsAccountDynamoDBRepository) GetAccount(name string) (models.AwsAccount, error) {
	sandbox := models.AwsAccount{Name: name}

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
	output, errget := a.Svc.GetItem(input)

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
		return models.AwsAccount{}, errget
	}

	if len(output.Item) == 0 {
		return models.AwsAccount{}, ErrAccountNotFound
	}

	if err := dynamodbattribute.UnmarshalMap(output.Item, &sandbox); err != nil {
		log.Logger.Error("Unmarshalling", err)
		return models.AwsAccount{}, err
	}
	log.Logger.Info("GetItem succeeded", slog.String("sandbox", sandbox.Name))
	return sandbox, nil
}

// GetAccounts returns the list of accounts from dynamodb
func (a *AwsAccountDynamoDBRepository) GetAccounts() ([]models.AwsAccount, error) {
	filters := []expression.ConditionBuilder{}
	return getAccounts(a.Svc, filters)
}

// GetAccountsToCleanup returns the list of accounts from dynamodb
func (a *AwsAccountDynamoDBRepository) GetAccountsToCleanup() ([]models.AwsAccount, error) {
	filters := []expression.ConditionBuilder{}
	filter := expression.Name("to_cleanup").Equal(expression.Value(true))
	filters = append(filters, filter)
	return getAccounts(a.Svc, filters)
}

func getAccounts(svc *dynamodb.DynamoDB,filters []expression.ConditionBuilder) ([]models.AwsAccount, error) {
	accounts := []models.AwsAccount{}

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
			accounts = append(accounts, BuildAccounts(page)...)
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
		return []models.AwsAccount{}, errscan
	}

	return accounts, nil
}
