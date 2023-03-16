package main

import (
	"flag"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rhpds/sandbox/internal/account"
	"github.com/rhpds/sandbox/internal/log"
	"net/http"
	"os"
	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"time"
)

var interval = 30 * time.Second
var debugFlag bool

func parseFlags() {
	// Option to show event
	flag.BoolVar(&debugFlag, "debug", false, "Debug mode.\nEnvironment variable: DEBUG\n")

	flag.Parse()
	if e := os.Getenv("DEBUG"); e != "" && e != "false" {
		debugFlag = true
	}
}


func serve() {
	log.Out.Println("promhttp Listening on port 2112")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}

func createMetrics() {

	gaugeVec := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "aws_sandbox_usage",
			Help: "Accounts in use",
		},
		[]string{"name", "status", "to_cleanup"},
	)

	used := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aws_sandbox_total_used",
		Help: "Total accounts in use",
	})

	toCleanup := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aws_sandbox_total_to_cleanup",
		Help: "Total accounts in the queue to be cleaned up",
	})

	total := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aws_sandbox_total",
		Help: "Total accounts",
	})

	sandboxdb.SetSession()

	// Update metrics every 30 seconds
	go func() {
		for {
			// no filter, we grab all accounts at once, then we filter because the DB is not that big.
			filters := []expression.ConditionBuilder{}
			accounts, err := sandboxdb.GetAccounts(filters)
			if err != nil {
				log.Err.Fatal(err)
			}
			used.Set(float64(account.CountUsed(accounts)))
			toCleanup.Set(float64(account.CountToCleanup(accounts)))
			total.Set(float64(len(accounts)))
			gaugeVec.Reset()
			for _, sandbox := range accounts {

				var status string
				var value float64
				toCleanup := "false"

				if sandbox.Available {
					status = "available"
					value = 0
				} else {
					status = "in-use"
					value = 1
				}

				if sandbox.ToCleanup {
					toCleanup = "true"
				}

				gaugeVec.WithLabelValues(sandbox.Name, status, toCleanup).Set(value)
			}
			time.Sleep(interval)
		}
	}()
}
func checkEnv() {
	if os.Getenv("AWS_PROFILE") == "" &&  os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		log.Err.Fatal("You must define env var AWS_PROFILE or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY")
	}
	if os.Getenv("AWS_PROFILE") != "" &&  os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		log.Err.Fatal("You must chose between AWS_PROFILE and AWS_ACCESS_KEY_ID")
	}

	if os.Getenv("AWS_REGION") == "" {
		os.Setenv("AWS_REGION", "us-east-1")
	}
}

func main() {
	parseFlags()
	log.InitLoggers(debugFlag)

	checkEnv()

	createMetrics()

	serve()
}
