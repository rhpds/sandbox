package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	sandboxdb "github.com/rhpds/sandbox/internal/dynamodb"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
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

func createMetrics(dbPool *pgxpool.Pool) {

	gaugeVec := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "aws_sandbox_usage",
			Help: "Accounts in use",
		},
		[]string{"name", "status", "to_cleanup", "reservation"},
	)

	gaugeLifecycleEvents := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sandbox_lifecycle_instance_events",
			Help: "Lifecycle events",
		},
		[]string{"resource_type", "region", "instance_type", "event_type"},
	)

	gaugeOcpSandboxStats := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sandbox_ocp_sandbox_stats",
			Help: "OCP Sandbox stats",
		},
		[]string{"resource_type", "cluster_name", "to_cleanup", "status"},
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
				log.Err.Println(err)
				time.Sleep(interval)
				continue
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

				gaugeVec.WithLabelValues(
					sandbox.Name,
					status,
					toCleanup,
					sandbox.Reservation).Set(value)
			}
			time.Sleep(interval)
		}
	}()

	if dbPool == nil {
		return
	}
	go func() {
		for {
			events, err := GetLifecycleInstanceEvents(dbPool)
			if err != nil {
				log.Err.Println(err)
				time.Sleep(interval)
				continue
			}
			gaugeLifecycleEvents.Reset()
			for _, event := range events {
				gaugeLifecycleEvents.WithLabelValues(
					event.ResourceType,
					event.Region,
					event.InstanceType,
					event.EventType,
				).Set(float64(event.Count))
			}

			gaugeOcpSandboxStats.Reset()
			ocpStats, err := GetOcpSandboxStats(dbPool)
			if err != nil {
				log.Err.Println(err)
				time.Sleep(interval)
				continue
			}

			for _, stat := range ocpStats {
				var toCleanup string
				if stat.ToCleanup {
					toCleanup = "true"
				} else {
					toCleanup = "false"
				}

				gaugeOcpSandboxStats.WithLabelValues(
					stat.ResourceType,
					stat.ClusterName,
					toCleanup,
					stat.Status,
				).Set(float64(stat.Count))
			}

			time.Sleep(interval)
		}
	}()
}

type LifecycleEvent struct {
	ResourceType string
	Region       string
	InstanceType string
	EventType    string
	Count        int
}

func GetLifecycleInstanceEvents(dbpool *pgxpool.Pool) ([]LifecycleEvent, error) {
	rows, err := dbpool.Query(
		context.Background(),
		`SELECT resource_type,
                event_data->>'region' as iregion,
                event_data->>'instance_type' as itype,
                event_type, count(*)
         FROM lifecycle_events WHERE resource_type = 'AwsSandbox' GROUP BY resource_type, iregion, itype, event_type;`,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	events := []LifecycleEvent{}

	for rows.Next() {
		var event LifecycleEvent
		err := rows.Scan(&event.ResourceType, &event.Region, &event.InstanceType, &event.EventType, &event.Count)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

type OcpSandboxStats struct {
	ResourceType string
	ClusterName  string
	ToCleanup    bool
	Status       string
	CleanupCount int
	Count        int
}

func GetOcpSandboxStats(dbPool *pgxpool.Pool) ([]OcpSandboxStats, error) {
	rows, err := dbPool.Query(
		context.Background(),
		`SELECT
			resource_type,
			resource_data->>'ocp_cluster' as cluster_name,
			to_cleanup,
			status,
			count(*)
		FROM resources
		WHERE resource_type = 'OcpSandbox'
			AND resource_data ? 'ocp_cluster'
		GROUP BY resource_type, cluster_name, to_cleanup, status;`,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	stats := []OcpSandboxStats{}

	for rows.Next() {
		var stat OcpSandboxStats
		err := rows.Scan(
			&stat.ResourceType,
			&stat.ClusterName,
			&stat.ToCleanup,
			&stat.Status,
			&stat.Count)
		if err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}

	return stats, nil
}

// Build info
var Version = "development"
var buildTime = "undefined"
var buildCommit = "HEAD"

func main() {
	var dbPool *pgxpool.Pool
	if os.Getenv("DATABASE_URL") != "" {
		connStr := os.Getenv("DATABASE_URL")
		var err error
		dbPool, err = pgxpool.Connect(context.Background(), connStr)

		if err != nil {
			log.Err.Fatal(err)
		}
		defer dbPool.Close()
	}

	parseFlags()
	log.InitLoggers(debugFlag, []slog.Attr{
		slog.String("version", Version),
		slog.String("buildTime", buildTime),
		slog.String("buildCommit", buildCommit),
	})

	sandboxdb.CheckEnv()

	createMetrics(dbPool)

	serve()
}
