package models
import (
	"sort"
	"time"
	"strconv"
)

type AwsAccount struct {
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

// AwsAccountRepository interface to interact with different databases:
// dynamodb and postgresql
type AwsAccountRepository interface {
	GetAccount(name string) (AwsAccount, error)
	GetAccounts() ([]AwsAccount, error)
	GetAccountsToCleanup() ([]AwsAccount, error)
}

// Used return the account in use
func Used(accounts []AwsAccount) []AwsAccount {
	r := []AwsAccount{}
	for _, i := range accounts {
		if !i.Available {
			r = append(r, i)
		}
	}
	return r
}

// CountAvailable return the number of accounts not in use
func CountAvailable(accounts []AwsAccount) int {
	total := 0

	for _, sandbox := range accounts {
		if sandbox.Available {
			total = total + 1
		}
	}

	return total
}

// CountUsed return the number of accounts in use
func CountUsed(accounts []AwsAccount) int {
	return len(accounts) - CountAvailable(accounts)
}

// CountToCleanup return the number of accounts to cleanup
func CountToCleanup(accounts []AwsAccount) int {
	total := 0

	for _, sandbox := range accounts {
		if sandbox.ToCleanup {
			total = total + 1
		}
	}

	return total
}

// SortAccounts
func SortAccounts(by string, accounts []AwsAccount) []AwsAccount {
	_accounts := append([]AwsAccount{}, accounts...)

	sort.SliceStable(_accounts, func(i, j int) bool {
		if by == "name" {
			return _accounts[i].NameInt < _accounts[j].NameInt
		}

		return _accounts[i].UpdateTime > _accounts[j].UpdateTime

	})
	return _accounts
}


// CountOlder returns the number of accounts in use for more than N day
func CountOlder(duration time.Duration, accounts []AwsAccount) (int, error) {
	total := 0

	for _, sandbox := range accounts {
		ti, err := strconv.ParseInt(strconv.FormatFloat(sandbox.UpdateTime, 'f', 0, 64), 10, 64)
		return 0, err

		updatetime := time.Unix(ti, 0)
		if time.Now().Sub(updatetime) < duration {
			total = total + 1
		}
	}

	return total, nil
}
