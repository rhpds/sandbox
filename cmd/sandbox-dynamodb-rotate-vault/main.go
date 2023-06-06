package main

import (
	"flag"
	"fmt"
	"golang.org/x/term"
	"os"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/sosedoff/ansible-vault-go"

	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"
)

func main() {
	log.InitLoggers(false)

	var sandboxName string

	flag.StringVar(&sandboxName, "sandbox", "all", "Sandbox name")
	flag.Parse()

	fmt.Println("Old vault key: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}

	old := strings.Trim(string(pw), "\r\n\t ")

	fmt.Println("New vault key: ")
	pw, err = term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}
	new := strings.Trim(string(pw), "\r\n\t ")

	accountProvider := sandboxdb.NewAwsAccountDynamoDBProviderWithSecret(old)

	var accounts []sandboxdb.AwsAccountDynamoDB
	if sandboxName != "all" {
		account, err := sandboxdb.GetAccount(accountProvider.Svc, sandboxName)
		if err != nil {
			fmt.Println("Error reading account", err)
			os.Exit(1)
		}

		accounts = append(accounts, account)
	} else {
		filter := expression.Name("name").AttributeExists()
		accounts, err = sandboxdb.GetAccounts(accountProvider.Svc, filter, -1)
	}

	if err != nil {
		fmt.Println("Error reading accounts", err)
		os.Exit(1)
	}

	for _, account := range accounts {
		str, err := vault.Decrypt(account.AwsSecretAccessKey, old)

		if err != nil {
			fmt.Println("Error decrypting secret", err)
			os.Exit(1)
		}

		enc, err := vault.Encrypt(str, new)

		if err != nil {
			fmt.Println("Error encrypting secret", err)
			os.Exit(1)
		}

		account.AwsSecretAccessKey = enc

		// Update dynamodb item
		_, err = accountProvider.Svc.UpdateItem(&dynamodb.UpdateItemInput{
			TableName: aws.String(os.Getenv("dynamodb_table")),
			Key: map[string]*dynamodb.AttributeValue{
				"name": {
					S: aws.String(account.Name),
				},
			},
			UpdateExpression: aws.String("SET aws_secret_access_key = :tc"),
			ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
				":tc": {
					S: aws.String(enc),
				},
			},
		})
		if err != nil {
			log.Logger.Error("error updating the sandbox secret", "name", account.Name, "error", err)
			os.Exit(1)
		}

		fmt.Println("done", account.Name)
	}
}
