package account
import (
	"sort"
	"time"
	"strconv"
)

// Used return the account in use
func Used(accounts []Account) []Account {
	r := []Account{}
	for _, i := range accounts {
		if !i.Available {
			r = append(r, i)
		}
	}
	return r
}

// CountAvailable return the number of accounts not in use
func CountAvailable(accounts []Account) int {
	total := 0

	for _, sandbox := range accounts {
		if sandbox.Available {
			total = total + 1
		}
	}

	return total
}

// CountUsed return the number of accounts in use
func CountUsed(accounts []Account) int {
	return len(accounts) - CountAvailable(accounts)
}

// CountToCleanup return the number of accounts to cleanup
func CountToCleanup(accounts []Account) int {
	total := 0

	for _, sandbox := range accounts {
		if sandbox.ToCleanup {
			total = total + 1
		}
	}

	return total
}

// SortUpdateTime sorts accounts by update time
func SortUpdateTime(accounts []Account) []Account {
	_accounts := append([]Account{}, accounts...)

	sort.SliceStable(_accounts, func(i, j int) bool {
		return _accounts[i].UpdateTime > _accounts[j].UpdateTime
	})
	return _accounts
}


// CountOlder returns the number of accounts in use for more than N day
func CountOlder(duration time.Duration, accounts []Account) (int, error) {
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
