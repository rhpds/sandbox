package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Operational counters and histograms for rate-limit advisory locks.
// These are incremented inline by model code to give real-time visibility
// into lock contention and rate-limit decisions.

var (
	RateLimitCheckTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sandbox_ratelimit_check_total",
			Help: "Total rate-limit checks, labeled by cluster and result (allowed, denied, error)",
		},
		[]string{"cluster", "result"},
	)
	RateLimitLockWaitSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sandbox_ratelimit_lock_wait_seconds",
			Help:    "Time spent waiting for advisory locks during rate-limit checks",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"cluster", "operation"},
	)
	SlotReservationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sandbox_ratelimit_slot_reservations_total",
			Help: "Total successful slot reservations by cluster",
		},
		[]string{"cluster"},
	)
	QueueDequeueTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sandbox_queue_dequeue_total",
			Help: "Total number of resources dequeued from the provision queue",
		},
	)
	QueueRescuerProcessedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "sandbox_queue_rescuer_processed_total",
			Help: "Total number of resources processed by the rescuer (orphan recovery). High values indicate pod instability or local processor issues.",
		},
	)
	PreCheckTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sandbox_ratelimit_precheck_total",
			Help: "Total pre-check results (all_limited, has_capacity, error)",
		},
		[]string{"result"},
	)
)
