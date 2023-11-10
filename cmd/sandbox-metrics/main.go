package main

import (
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
	"log/slog"
	"net/http"
	"os"
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
		[]string{"name", "status", "to_cleanup", "reservation"},
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

	accountProvider := sandboxdb.NewAwsAccountDynamoDBProvider()

	// Update metrics every 30 seconds
	go func() {
		for {
			// no filter, we grab all accounts at once, then we filter because the DB is not that big.
			accounts, err := accountProvider.FetchAll()
			if err != nil {
				log.Err.Fatal(err)
			}
			used.Set(float64(models.CountUsed(accounts)))
			toCleanup.Set(float64(models.CountToCleanup(accounts)))
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

				gaugeVec.WithLabelValues(sandbox.Name, status, toCleanup, sandbox.Reservation).Set(value)
			}
			time.Sleep(interval)
		}
	}()
}

// Build info
var Version = "development"
var buildTime = "undefined"
var buildCommit = "HEAD"

func main() {
	parseFlags()
	log.InitLoggers(debugFlag, []slog.Attr{
		slog.String("version", Version),
		slog.String("buildTime", buildTime),
		slog.String("buildCommit", buildCommit),
	})

	sandboxdb.CheckEnv()

	createMetrics()

	serve()
}
