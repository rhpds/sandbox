package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
)

// -----------------------------------------------------------------------
// Rate-limit gauges (refreshed by background collector)
// -----------------------------------------------------------------------

var (
	rateLimitProvisionCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sandbox_ratelimit_provision_count",
			Help: "Current number of provisions within the rate window for a cluster",
		},
		[]string{"cluster"},
	)
	rateLimitMax = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sandbox_ratelimit_max",
			Help: "Configured provision rate limit for a cluster",
		},
		[]string{"cluster"},
	)
	rateLimitAvailableSlots = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sandbox_ratelimit_available_slots",
			Help: "Available provision slots within the rate window for a cluster",
		},
		[]string{"cluster"},
	)
)

// -----------------------------------------------------------------------
// Queue collector — queries DB on every /metrics scrape for real-time values
// -----------------------------------------------------------------------

var (
	queuedResourcesDesc = prometheus.NewDesc(
		"sandbox_queued_resources_total",
		"Total number of queued OcpSandbox resources",
		nil, nil,
	)
	queuedPlacementsDesc = prometheus.NewDesc(
		"sandbox_queued_placements_total",
		"Total number of placements in queued status",
		nil, nil,
	)
)

type queueCollector struct {
	dbPool *pgxpool.Pool
}

func (c *queueCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- queuedResourcesDesc
	ch <- queuedPlacementsDesc
}

func (c *queueCollector) Collect(ch chan<- prometheus.Metric) {
	var queuedResources int
	if err := c.dbPool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM resources
		 WHERE resource_type = 'OcpSandbox' AND status = 'queued'`,
	).Scan(&queuedResources); err != nil {
		log.Logger.Error("metrics: error counting queued resources", "error", err)
	} else {
		ch <- prometheus.MustNewConstMetric(queuedResourcesDesc, prometheus.GaugeValue, float64(queuedResources))
	}

	var queuedPlacements int
	if err := c.dbPool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM placements WHERE status = 'queued'`,
	).Scan(&queuedPlacements); err != nil {
		log.Logger.Error("metrics: error counting queued placements", "error", err)
	} else {
		ch <- prometheus.MustNewConstMetric(queuedPlacementsDesc, prometheus.GaugeValue, float64(queuedPlacements))
	}
}

func registerQueueCollector(dbPool *pgxpool.Pool) {
	prometheus.MustRegister(&queueCollector{dbPool: dbPool})
}

// -----------------------------------------------------------------------
// PostgreSQL lock gauges (refreshed by background collector)
// -----------------------------------------------------------------------

var (
	pgAdvisoryLocksHeld = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_advisory_locks_held",
			Help: "Number of advisory locks currently held, labeled by cluster name (or lock_key if unknown)",
		},
		[]string{"cluster", "lock_key"},
	)
	pgAdvisoryLocksWaiting = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_advisory_locks_waiting",
			Help: "Number of backends waiting to acquire advisory locks, labeled by cluster name",
		},
		[]string{"cluster", "lock_key"},
	)
	pgLocksTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_locks_total",
			Help: "Total number of PostgreSQL locks by type and mode",
		},
		[]string{"locktype", "mode", "granted"},
	)
	pgActiveConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_connections_active",
			Help: "Number of active (non-idle) PostgreSQL connections from this application",
		},
	)
	pgIdleConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_connections_idle",
			Help: "Number of idle PostgreSQL connections from this application",
		},
	)
	pgPoolTotalConns = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_pool_total_conns",
			Help: "Total connections in the pgxpool connection pool",
		},
	)
	pgPoolIdleConns = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_pool_idle_conns",
			Help: "Idle connections in the pgxpool connection pool",
		},
	)
	pgPoolMaxConns = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_pool_max_conns",
			Help: "Maximum connections configured in the pgxpool connection pool",
		},
	)
	pgLongestLockWaitSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "sandbox_pg_longest_lock_wait_seconds",
			Help: "Duration in seconds of the longest-waiting lock acquisition",
		},
	)
)

// Operational counters/histograms live in internal/metrics so model code
// can increment them directly. They are auto-registered with the default
// Prometheus registry and served by promhttp.Handler().

// -----------------------------------------------------------------------
// Background collector
// -----------------------------------------------------------------------

// startMetricsCollector starts a background goroutine that periodically
// refreshes Prometheus metrics for rate limiting, queue state, and PG locks.
func startMetricsCollector(ctx context.Context, dbPool *pgxpool.Pool, ocpProvider *models.OcpSandboxProvider) {
	var mu sync.Mutex

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		collect := func() {
			mu.Lock()
			defer mu.Unlock()
			collectRateLimitMetrics(dbPool, ocpProvider)
			collectPgLockMetrics(dbPool, ocpProvider)
			collectPgPoolMetrics(dbPool)
		}
		collect()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				collect()
			}
		}
	}()
}

// clusterNameByLockKey builds a reverse lookup from FNV32a hash → cluster name.
func clusterNameByLockKey(ocpProvider *models.OcpSandboxProvider) map[int64]string {
	clusters, err := ocpProvider.GetOcpSharedClusterConfigurations()
	if err != nil {
		return nil
	}
	m := make(map[int64]string, len(clusters))
	for _, c := range clusters {
		h := fnv.New32a()
		h.Write([]byte(c.Name))
		m[int64(h.Sum32())] = c.Name
	}
	return m
}

func collectRateLimitMetrics(dbPool *pgxpool.Pool, ocpProvider *models.OcpSandboxProvider) {
	clusters, err := ocpProvider.GetOcpSharedClusterConfigurations()
	if err != nil {
		log.Logger.Error("metrics: error fetching clusters", "error", err)
		return
	}

	rateLimitProvisionCount.Reset()
	rateLimitMax.Reset()
	rateLimitAvailableSlots.Reset()

	for _, cluster := range clusters {
		if cluster.Settings.ProvisionRateLimit == nil {
			continue
		}

		rateLimitMax.WithLabelValues(cluster.Name).Set(float64(*cluster.Settings.ProvisionRateLimit))

		_, availableSlots, err := cluster.IsRateLimited()
		if err != nil {
			log.Logger.Error("metrics: error checking rate limit",
				"cluster", cluster.Name, "error", err)
			continue
		}

		limit := float64(*cluster.Settings.ProvisionRateLimit)
		avail := float64(availableSlots)
		rateLimitProvisionCount.WithLabelValues(cluster.Name).Set(limit - avail)
		rateLimitAvailableSlots.WithLabelValues(cluster.Name).Set(avail)
	}
}

func collectPgLockMetrics(dbPool *pgxpool.Pool, ocpProvider *models.OcpSandboxProvider) {
	// Build reverse lookup: FNV hash → cluster name
	lookup := clusterNameByLockKey(ocpProvider)

	pgAdvisoryLocksHeld.Reset()
	pgAdvisoryLocksWaiting.Reset()

	// Advisory locks detail — group by lock key and granted status
	rows, err := dbPool.Query(
		context.Background(),
		`SELECT classid::bigint, granted, count(*)
		 FROM pg_locks
		 WHERE locktype = 'advisory'
		 GROUP BY classid, granted`,
	)
	if err != nil {
		log.Logger.Error("metrics: error querying pg_locks (advisory)", "error", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var lockKey int64
			var granted bool
			var count int
			if err := rows.Scan(&lockKey, &granted, &count); err != nil {
				continue
			}
			clusterName := lookup[lockKey]
			if clusterName == "" {
				clusterName = "unknown"
			}
			keyStr := fmt.Sprintf("%d", lockKey)
			if granted {
				pgAdvisoryLocksHeld.WithLabelValues(clusterName, keyStr).Set(float64(count))
			} else {
				pgAdvisoryLocksWaiting.WithLabelValues(clusterName, keyStr).Set(float64(count))
			}
		}
	}

	// All locks by type — general overview
	pgLocksTotal.Reset()
	rows2, err := dbPool.Query(
		context.Background(),
		`SELECT locktype, mode, granted::text, count(*)
		 FROM pg_locks
		 GROUP BY locktype, mode, granted`,
	)
	if err != nil {
		log.Logger.Error("metrics: error querying pg_locks (all)", "error", err)
	} else {
		defer rows2.Close()
		for rows2.Next() {
			var locktype, mode, granted string
			var count int
			if err := rows2.Scan(&locktype, &mode, &granted, &count); err != nil {
				continue
			}
			pgLocksTotal.WithLabelValues(locktype, mode, granted).Set(float64(count))
		}
	}

	// Longest lock wait
	var longestWait *float64
	err = dbPool.QueryRow(
		context.Background(),
		`SELECT EXTRACT(EPOCH FROM max(now() - a.query_start))
		 FROM pg_locks l
		 JOIN pg_stat_activity a ON l.pid = a.pid
		 WHERE NOT l.granted`,
	).Scan(&longestWait)
	if err != nil {
		log.Logger.Error("metrics: error querying longest lock wait", "error", err)
	} else if longestWait != nil {
		pgLongestLockWaitSeconds.Set(*longestWait)
	} else {
		pgLongestLockWaitSeconds.Set(0)
	}

	// Active vs idle connections
	var active, idle int
	err = dbPool.QueryRow(
		context.Background(),
		`SELECT
			count(*) FILTER (WHERE state != 'idle' AND state IS NOT NULL),
			count(*) FILTER (WHERE state = 'idle')
		 FROM pg_stat_activity
		 WHERE pid != pg_backend_pid()`,
	).Scan(&active, &idle)
	if err != nil {
		log.Logger.Error("metrics: error querying pg_stat_activity", "error", err)
	} else {
		pgActiveConnections.Set(float64(active))
		pgIdleConnections.Set(float64(idle))
	}
}

func collectPgPoolMetrics(dbPool *pgxpool.Pool) {
	stat := dbPool.Stat()
	pgPoolTotalConns.Set(float64(stat.TotalConns()))
	pgPoolIdleConns.Set(float64(stat.IdleConns()))
	pgPoolMaxConns.Set(float64(stat.MaxConns()))
}
