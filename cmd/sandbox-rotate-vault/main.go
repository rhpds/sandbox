package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/term"
	"log/slog"
	"os"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/sosedoff/ansible-vault-go"

	"github.com/jackc/pgx/v4/pgxpool"
	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"
)

// Build info
var Version = "development"
var buildTime = "undefined"
var buildCommit = "HEAD"

func main() {
	log.InitLoggers(false, []slog.Attr{
		slog.String("version", Version),
		slog.String("buildTime", buildTime),
		slog.String("buildCommit", buildCommit),
	})

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

		// Build update expression and values
		updateExpression := "SET aws_secret_access_key = :secret"
		expressionAttrValues := map[string]*dynamodb.AttributeValue{
			":secret": {
				S: aws.String(enc),
			},
		}

		// Rotate custom_data if present
		if account.CustomData != "" {
			customDataStr, err := vault.Decrypt(account.CustomData, old)
			if err != nil {
				fmt.Println("Error decrypting custom_data for", account.Name, ":", err)
				// Skip custom_data rotation for this account, but continue with secret
			} else {
				customDataEnc, err := vault.Encrypt(customDataStr, new)
				if err != nil {
					fmt.Println("Error encrypting custom_data for", account.Name, ":", err)
					os.Exit(1)
				}
				updateExpression += ", custom_data = :customdata"
				expressionAttrValues[":customdata"] = &dynamodb.AttributeValue{
					S: aws.String(customDataEnc),
				}
			}
		}

		// Update dynamodb item
		_, err = accountProvider.Svc.UpdateItem(&dynamodb.UpdateItemInput{
			TableName: aws.String(os.Getenv("dynamodb_table")),
			Key: map[string]*dynamodb.AttributeValue{
				"name": {
					S: aws.String(account.Name),
				},
			},
			UpdateExpression:          aws.String(updateExpression),
			ExpressionAttributeValues: expressionAttrValues,
		})
		if err != nil {
			log.Logger.Error("error updating the sandbox secret", "name", account.Name, "error", err)
			os.Exit(1)
		}

		fmt.Println("done", account.Name)
	}

	// connect to postgresql using DATABASE_URL env variable
	if os.Getenv("DATABASE_URL") == "" {
		log.Logger.Error("DATABASE_URL environment variable not set")
		os.Exit(1)
	}
	connStr := os.Getenv("DATABASE_URL")

	dbPool, err := pgxpool.Connect(context.Background(), connStr)
	if err != nil {
		log.Logger.Error("Error opening database connection", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// Update PostgreSQL columns that are encrypted
	// update ocp_shared_cluster_configurations set kubeconfig = pgp_sym_encrypt( pgp_sym_decrypt(kubeconfig::bytea, 'old'), 'new');

	if _, err = dbPool.Exec(
		context.Background(),
		`UPDATE ocp_shared_cluster_configurations
			SET kubeconfig = pgp_sym_encrypt( pgp_sym_decrypt(kubeconfig::bytea, $1), $2),
				token = pgp_sym_encrypt( pgp_sym_decrypt(token::bytea, $1), $2)`,
		old, new); err != nil {

		log.Logger.Error("Error updating ocp_shared_cluster_configurations", "error", err)
		os.Exit(1)
	}

	if _, err = dbPool.Exec(
		context.Background(),
		`UPDATE ocp_shared_cluster_configurations
			SET deployer_admin_sa_token = pgp_sym_encrypt( pgp_sym_decrypt(deployer_admin_sa_token::bytea, $1), $2)
			WHERE deployer_admin_sa_token IS NOT NULL`,
		old, new); err != nil {

		log.Logger.Error("Error updating ocp_shared_cluster_configurations deployer_admin_sa_token", "error", err)
		os.Exit(1)
	}

	fmt.Println("done ocp_shared_cluster_configurations")

	if _, err = dbPool.Exec(
		context.Background(),
		"UPDATE resources SET resource_credentials = pgp_sym_encrypt( pgp_sym_decrypt(resource_credentials::bytea, $1), $2)",
		old, new); err != nil {

		log.Logger.Error("Error updating resources", "error", err)
		os.Exit(1)
	}

	fmt.Println("done resources")

	if _, err = dbPool.Exec(
		context.Background(),
		"UPDATE dns_account_configurations SET aws_secret_access_key = pgp_sym_encrypt( pgp_sym_decrypt(aws_secret_access_key::bytea, $1), $2)",
		old, new); err != nil {

		log.Logger.Error("Error updating dns_account_configurations", "error", err)
		os.Exit(1)
	}

	fmt.Println("done dns_account_configurations")

	if _, err = dbPool.Exec(
		context.Background(),
		"UPDATE ibm_resource_group_account_configurations SET apikey = pgp_sym_encrypt( pgp_sym_decrypt(apikey::bytea, $1), $2)",
		old, new); err != nil {

		log.Logger.Error("Error updating ibm_resource_group_account_configurations", "error", err)
		os.Exit(1)
	}

	fmt.Println("done ibm_resource_group_account_configurations")
}
