package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
)

var csvFlag bool
var allFlag bool
var debugFlag bool
var toCleanupFlag bool
var noHeadersFlag bool
var padding = 2
var versionFlag bool
var sortFlag string

// Build info
var Version = "development"
var buildTime = "undefined"
var buildCommit = "HEAD"

type accountPrint models.AwsAccount

func (a accountPrint) String() string {
	var separator string
	if csvFlag {
		separator = ","
	} else {
		separator = "\t"
	}
	diff := time.Since(a.UpdatedAt)

	var supdatetime string
	if csvFlag {
		supdatetime = a.UpdatedAt.Format(time.RFC3339)
	} else {
		supdatetime = fmt.Sprintf("%s (%dd)", a.UpdatedAt.Format("2006-01-02 15:04"), int(diff.Hours()/24))
	}

	var toCleanupString string
	/* Do not write true | false to not break current scripts that filter
	   using true|false on the whole line */
	if a.ToCleanup {
		if a.ConanStatus == "cleanup in progress" {
			toCleanupString = fmt.Sprintf("IN_PROGRESS (%s)", a.ConanHostname)
		} else {
			toCleanupString = "TO_CLEANUP"
		}
	} else {
		toCleanupString = "no"
	}

	return strings.Join([]string{
		a.Name,
		strconv.FormatBool(a.Available),
		a.Annotations["guid"],
		a.Annotations["env_type"],
		a.AccountID,
		a.Annotations["owner"],
		a.Annotations["owner_email"],
		a.Zone,
		a.HostedZoneID,
		supdatetime,
		a.ServiceUuid,
		toCleanupString,
		a.Annotations["comment"],
	}, separator)
}

func printHeaders(w *tabwriter.Writer) {
	if noHeadersFlag {
		return
	}

	var separator string
	if csvFlag {
		separator = ","
	} else {
		separator = "\t"
	}

	headers := []string{
		"Name",
		"Avail",
		"Guid",
		"Envtype",
		"AccountId",
		"Owner",
		"OwnerEmail",
		"Zone",
		"HostedZoneId",
		"UpdateTime",
		"UUID",
		"ToCleanup?",
		"Comment",
	}
	for _, h := range headers {
		fmt.Fprintf(w, "%s%s", h, separator)
	}
	fmt.Fprintln(w)
}

func parseFlags() {
	// Option to show event
	flag.BoolVar(&csvFlag, "csv", false, "Use CSV format to print accounts.")
	flag.BoolVar(&allFlag, "all", false, "Just print all sandboxes.")
	flag.BoolVar(&toCleanupFlag, "to-cleanup", false, "Print all marked for cleanup.")
	flag.BoolVar(&noHeadersFlag, "no-headers", false, "Don't print headers.")
	flag.BoolVar(&debugFlag, "debug", false, "Debug mode.\nEnvironment variable: DEBUG\n")
	flag.BoolVar(&versionFlag, "version", false, "Print build version.")
	flag.StringVar(&sortFlag, "sort", "UpdateTime", "Sort by column. Possible values: [UpdateTime, Name]")

	flag.Parse()

	if e := os.Getenv("DEBUG"); e != "" && e != "false" {
		debugFlag = true
	}

	sortFlag = strings.ToLower(sortFlag)
	if sortFlag != "updatetime" && sortFlag != "name" {
		fmt.Print("possible values for --sort: Name, UpdateTime")
		os.Exit(2)
	}

	if versionFlag {
		fmt.Println("Version:", Version)
		fmt.Println("Build time:", buildTime)
		fmt.Println("Build commit:", buildCommit)
		os.Exit(0)
	}
}

func printMostRecentlyUsed(accounts []models.AwsAccount) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', 0)
	m := models.Sort(models.Used(accounts), "UpdateTime")

	fmt.Println()
	fmt.Println("# Most recently used sandboxes")
	fmt.Println()
	printHeaders(w)
	for i := 0; i < 10; i++ {
		fmt.Fprintln(w, accountPrint(m[i]))
	}
	w.Flush()
}

func printOldest(accounts []models.AwsAccount) {
	m := models.Sort(models.Used(accounts), "UpdateTime")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', 0)

	fmt.Println()
	fmt.Println("# Oldest sandboxes in use")
	fmt.Println()
	printHeaders(w)
	for i := 10; i >= 1; i-- {
		fmt.Fprintln(w, accountPrint(m[len(m)-i]))
	}
	w.Flush()
}

func printBroken(accounts []models.AwsAccount) {
	m := []string{}
	for _, sandbox := range accounts {
		if sandbox.Zone == "" {
			m = append(m, fmt.Sprintf("%v %v\n", accountPrint(sandbox), "Zone missing"))
		}
		if sandbox.HostedZoneID == "" {
			m = append(m, fmt.Sprintf("%v %v\n", accountPrint(sandbox), "HostedZoneId missing"))
		}
	}
	if len(m) > 0 {
		fmt.Println()
		fmt.Println("# Broken sandboxes")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', 0)
		printHeaders(w)
		for _, line := range m {
			fmt.Fprint(w, line)
		}
		w.Flush()
	}
}

func main() {
	parseFlags()
	log.InitLoggers(debugFlag)

	if os.Getenv("AWS_PROFILE") == "" {
		os.Setenv("AWS_PROFILE", "pool-manager")
	}
	if os.Getenv("AWS_REGION") == "" {
		os.Setenv("AWS_REGION", "us-east-1")
	}
	if os.Getenv("dynamodb_table") == "" {
		os.Setenv("dynamodb_table", "accounts")
	}

	accountProvider := sandboxdb.NewAwsAccountDynamoDBProvider()

	var accounts []models.AwsAccount
	var err error

	if toCleanupFlag {
		accounts, err = accountProvider.FetchAllToCleanup()
		if err != nil {
			log.Err.Fatal(err)
		}
	} else {
		accounts, err = accountProvider.FetchAll()
		if err != nil {
			log.Err.Fatal(err)
		}
	}

	accounts = models.Sort(accounts, sortFlag)

	if err != nil {
		log.Err.Fatal(err)
	}

	if allFlag || toCleanupFlag {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', 0)
		printHeaders(w)
		for _, sandbox := range accounts {
			fmt.Fprintln(w, accountPrint(sandbox))
		}
		w.Flush()
		os.Exit(0)
	}

	usedAccounts := models.Used(accounts)
	fmt.Println()
	fmt.Println("Total Used:", len(usedAccounts), "/", len(accounts))

	printMostRecentlyUsed(accounts)
	printOldest(accounts)
	printBroken(accounts)
}
