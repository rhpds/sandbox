package models

import (
	"errors"
	"github.com/rhpds/sandbox/internal/log"
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
	Kind string `json:"kind"` // "aws_account"

	Name         string `json:"name"`
	AccountID    string `json:"account_id"`
	Zone         string `json:"zone"`
	HostedZoneID string `json:"hosted_zone_id"`

	ConanStatus    string    `json:"conan_status,omitempty"`
	ConanTimestamp time.Time `json:"conan_timestamp,omitempty"`
	ConanHostname  string    `json:"conan_hostname,omitempty"`
}

type AwsAccountWithCreds struct {
	AwsAccount

	Credentials []any `json:"credentials"`
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
	FetchByName(name string) (AwsAccount, error)
	FetchAll() ([]AwsAccount, error)
	FetchAllToCleanup() ([]AwsAccount, error)
	FetchAllSorted(by string) ([]AwsAccount, error)
	FetchAllByServiceUuid(serviceUuid string) ([]AwsAccount, error)
	Request(service_uuid string, count int, annotations map[string]string) ([]AwsAccountWithCreds, error)
	MarkForCleanup(name string) error
	MarkForCleanupByServiceUuid(serviceUuid string) error
	DecryptSecret(encrypted string) (string, error)
	//Annotations(account AwsAccount) (map[string]string, error)
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
