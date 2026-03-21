package models

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/rhpds/sandbox/internal/config"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/metrics"
)

// ---------------------------------------------------------------------------
// Queue processor: local processor + rescuer architecture
//
// Exactly 1 + N goroutines per pod (1 local processor + N rescuers).
// The local processor handles resources queued by this pod (fast path).
// The rescuers handle all resources (orphan recovery from dead pods).
// ---------------------------------------------------------------------------

// queueProcessorLockID is a fixed advisory lock ID for the rescuer.
// Only one instance across all pods can hold this lock at a time, preventing
// race conditions when multiple rescuers poll concurrently.
const queueProcessorLockID = 0x53414E44424F5851 // "SANDBOXQ"

// StartQueueProcessor starts the background queue components:
//
//  1. Local processor — signal-driven, processes resources queued by this pod
//     (matching locality_id). Wakes up immediately when notified via QueueNotify.
//     After processing, retries every localPollInterval if resources remain queued.
//
//  2. Rescuer(s) — poll every rescuerInterval, process ALL queued resources
//     regardless of locality. Use a global advisory lock to ensure only one
//     rescuer runs across all pods. Handle orphans from dead pods.
func (a *OcpSandboxProvider) StartQueueProcessor(ctx context.Context) {
	a.QueueNotify = make(chan string, 100)

	localPollInterval := 5 * time.Second
	if v := os.Getenv("QUEUE_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			localPollInterval = d
		}
	}

	rescuerInterval := 30 * time.Second
	if v := os.Getenv("QUEUE_RESCUER_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			rescuerInterval = d
		}
	}

	rescuerCount := 1
	if v := os.Getenv("QUEUE_RESCUERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			rescuerCount = n
		}
	}

	var localDelay time.Duration
	if v := os.Getenv("QUEUE_LOCAL_DELAY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			localDelay = d
		}
	}

	log.Logger.Info("QueueProcessor: starting",
		"locality", config.LocalityID,
		"rescuer_interval", rescuerInterval,
		"rescuer_count", rescuerCount,
		"local_poll_interval", localPollInterval,
		"local_delay", localDelay)

	// Local processor goroutine
	go a.runLocalProcessor(ctx, localPollInterval, localDelay)

	// Rescuer goroutines
	for i := 0; i < rescuerCount; i++ {
		rescuerID := i
		go a.runRescuer(ctx, rescuerID, rescuerInterval)
	}
}

// runLocalProcessor listens for QueueNotify signals and retries on a timer
// when resources remain queued (rate-limited).
func (a *OcpSandboxProvider) runLocalProcessor(ctx context.Context, pollInterval, delay time.Duration) {
	log.Logger.Info("QueueProcessor: local processor started",
		"locality", config.LocalityID,
		"poll_interval", pollInterval)

	var retryTimer <-chan time.Time // nil until resources remain queued

	for {
		select {
		case <-ctx.Done():
			log.Logger.Info("QueueProcessor: local processor stopping")
			return

		case svcUuid := <-a.QueueNotify:
			log.Logger.Info("QueueProcessor: local notification received",
				"serviceUuid", svcUuid, "locality", config.LocalityID)
			// Drain any additional notifications that arrived
			drained := 0
		drain:
			for {
				select {
				case <-a.QueueNotify:
					drained++
				default:
					break drain
				}
			}
			if drained > 0 {
				log.Logger.Info("QueueProcessor: drained additional notifications",
					"count", drained)
			}
			if delay > 0 {
				log.Logger.Info("QueueProcessor: local delay active, sleeping",
					"delay", delay)
				time.Sleep(delay)
			}
			remaining := a.processLocalQueue()
			if remaining > 0 {
				retryTimer = time.After(pollInterval)
			} else {
				retryTimer = nil
			}

		case <-retryTimer:
			remaining := a.processLocalQueue()
			if remaining > 0 {
				retryTimer = time.After(pollInterval)
			} else {
				retryTimer = nil
			}
		}
	}
}

// runRescuer polls on interval, acquires a global advisory lock, and processes
// stale queued resources from any locality.
func (a *OcpSandboxProvider) runRescuer(ctx context.Context, id int, interval time.Duration) {
	log.Logger.Info("QueueProcessor: rescuer started",
		"id", id, "interval", interval)
	for {
		select {
		case <-ctx.Done():
			log.Logger.Info("QueueProcessor: rescuer stopping", "id", id)
			return
		case <-time.After(interval):
			a.processRescuerQueue(interval)
		}
	}
}

// notifyQueue sends a non-blocking signal to the local queue processor
// that a resource was queued and needs processing.
func (a *OcpSandboxProvider) notifyQueue(serviceUuid string) {
	if a.QueueNotify == nil {
		return
	}
	select {
	case a.QueueNotify <- serviceUuid:
	default:
		// Channel full — local processor will pick it up on next drain
	}
}

// ---------------------------------------------------------------------------
// Queue fetching
// ---------------------------------------------------------------------------

// processLocalQueue processes queued resources that belong to this pod's
// locality. No global advisory lock — each pod only processes its own items.
// Returns the number of resources still queued after processing (so the caller
// can schedule a retry).
func (a *OcpSandboxProvider) processLocalQueue() int {
	queuedResources, err := a.FetchQueuedResourcesByLocality(config.LocalityID)
	if err != nil {
		log.Logger.Error("QueueProcessor: error fetching local queued resources", "error", err)
		return 0
	}
	if len(queuedResources) == 0 {
		return 0
	}
	log.Logger.Info("QueueProcessor: processing local queue",
		"count", len(queuedResources), "locality", config.LocalityID)
	a.processQueuedResourceList(queuedResources)

	// Re-fetch to see how many are still queued after processing
	remaining, err := a.FetchQueuedResourcesByLocality(config.LocalityID)
	if err != nil {
		return 0
	}
	return len(remaining)
}

// processRescuerQueue processes ALL queued resources regardless of locality.
// Uses a global advisory lock to ensure only one rescuer runs across all pods.
func (a *OcpSandboxProvider) processRescuerQueue(rescuerInterval time.Duration) {
	ctx := context.Background()

	// Acquire a transaction-scoped advisory lock. If another instance is
	// already processing the queue, skip this cycle.
	tx, err := a.DbPool.Begin(ctx)
	if err != nil {
		log.Logger.Error("QueueProcessor: rescuer error starting transaction", "error", err)
		return
	}
	defer tx.Rollback(ctx)

	var locked bool
	if err := tx.QueryRow(ctx,
		"SELECT pg_try_advisory_xact_lock($1)", queueProcessorLockID,
	).Scan(&locked); err != nil {
		log.Logger.Error("QueueProcessor: rescuer error acquiring advisory lock", "error", err)
		return
	}
	if !locked {
		return
	}

	// Fetch queued resources that haven't been checked recently.
	// Resources actively handled by a local processor will have a fresh
	// queue_checked_at and are skipped — the rescuer only picks up orphans.
	queuedResources, err := a.FetchStaleQueuedResources(rescuerInterval)
	if err != nil {
		log.Logger.Error("QueueProcessor: rescuer error fetching queued resources", "error", err)
		return
	}

	if len(queuedResources) == 0 {
		return
	}

	log.Logger.Info("QueueProcessor: rescuer processing queued resources",
		"count", len(queuedResources))
	metrics.QueueRescuerProcessedTotal.Add(float64(len(queuedResources)))

	// Stamp queue_checked_at on all resources while we hold the lock.
	// This prevents other rescuers from re-fetching the same resources
	// if they acquire the lock before we finish processing.
	for _, res := range queuedResources {
		a.stampQueueCheckedAt(res.ID, res.Name)
	}

	// Release the advisory lock before processing so we don't hold it
	// during potentially slow provisioning operations.
	if err := tx.Commit(ctx); err != nil {
		log.Logger.Error("QueueProcessor: rescuer error committing transaction", "error", err)
		return
	}

	a.processQueuedResourceList(queuedResources)
}

// FetchQueuedResources returns all OcpSandbox resources with status "queued",
// ordered by creation time (FIFO).
func (a *OcpSandboxProvider) FetchQueuedResources() ([]OcpSandboxWithCreds, error) {
	return a.fetchQueuedResources(
		`WHERE resource_type = 'OcpSandbox' AND status = 'queued'`,
	)
}

// FetchQueuedResourcesByLocality returns OcpSandbox resources with status "queued"
// that were queued by the given locality (pod), ordered by creation time (FIFO).
func (a *OcpSandboxProvider) FetchQueuedResourcesByLocality(localityID string) ([]OcpSandboxWithCreds, error) {
	return a.fetchQueuedResources(
		`WHERE resource_type = 'OcpSandbox'
		   AND status = 'queued'
		   AND resource_data->'queued_params'->>'locality_id' = $1`,
		localityID,
	)
}

// FetchStaleQueuedResources returns queued resources that haven't been checked
// by any processor within the given staleness threshold. Resources with a
// recent queue_checked_at are being actively handled by a local processor
// and are skipped. Resources with no queue_checked_at are always included.
func (a *OcpSandboxProvider) FetchStaleQueuedResources(staleAfter time.Duration) ([]OcpSandboxWithCreds, error) {
	return a.fetchQueuedResources(
		`WHERE resource_type = 'OcpSandbox'
		   AND status = 'queued'
		   AND (
		     resource_data->>'queue_checked_at' IS NULL
		     OR (resource_data->>'queue_checked_at')::timestamptz < now() - $1::interval
		   )`,
		fmt.Sprintf("%d seconds", int(staleAfter.Seconds())),
	)
}

// fetchQueuedResources is a shared helper for queued resource queries.
func (a *OcpSandboxProvider) fetchQueuedResources(whereClause string, args ...interface{}) ([]OcpSandboxWithCreds, error) {
	query := `SELECT
		resource_data, id, resource_name, resource_type,
		service_uuid, created_at, updated_at, status, cleanup_count
	FROM resources ` + whereClause + ` ORDER BY created_at ASC`

	rows, err := a.DbPool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var resources []OcpSandboxWithCreds
	for rows.Next() {
		var r OcpSandboxWithCreds
		if err := rows.Scan(
			&r, &r.ID, &r.Name, &r.Kind,
			&r.ServiceUuid, &r.CreatedAt, &r.UpdatedAt,
			&r.Status, &r.CleanupCount,
		); err != nil {
			return nil, err
		}
		r.Provider = a
		resources = append(resources, r)
	}
	return resources, nil
}

// ---------------------------------------------------------------------------
// Queue processing: orchestration + business logic
// ---------------------------------------------------------------------------

// processQueuedResourceList is the shared processing loop for both the local
// processor and the rescuer. For each resource it:
//  1. Stamps queue_checked_at (so the rescuer skips recently-checked resources)
//  2. Evaluates whether the resource can be dequeued (business logic)
//  3. CAS-transitions the resource from "queued" to "initializing"
//  4. Triggers provisioning for dequeued resources
func (a *OcpSandboxProvider) processQueuedResourceList(queuedResources []OcpSandboxWithCreds) {
	var toProvision []OcpSandboxWithCreds
	claimedClusters := make(map[string]bool)

	for _, res := range queuedResources {
		if res.QueuedParams == nil {
			log.Logger.Error("QueueProcessor: resource has no queued_params",
				"id", res.ID, "name", res.Name)
			continue
		}

		a.stampQueueCheckedAt(res.ID, res.Name)

		if !a.canDequeue(&res, claimedClusters) {
			continue
		}

		if a.casTransitionToInitializing(res) {
			toProvision = append(toProvision, res)
		}
	}

	for _, res := range toProvision {
		a.provisionDequeuedResource(res)
	}

	a.updateCompletedPlacements()
}

// canDequeue evaluates whether a queued resource can be dequeued right now.
// It checks cluster relation dependencies, finds schedulable clusters,
// and attempts to reserve a rate-limit slot. On success it marks all
// candidate clusters as claimed (FIFO guard) and returns true.
func (a *OcpSandboxProvider) canDequeue(res *OcpSandboxWithCreds, claimedClusters map[string]bool) bool {
	params := res.QueuedParams

	// Check cluster relation dependencies: if a referenced sibling is
	// still queued, skip this resource (try again next cycle).
	if len(params.ClusterRelation) > 0 {
		siblings, err := a.FetchAllByServiceUuid(res.ServiceUuid)
		if err != nil {
			log.Logger.Error("QueueProcessor: error fetching siblings",
				"error", err, "serviceUuid", res.ServiceUuid)
			return false
		}
		for _, rel := range params.ClusterRelation {
			for _, sibling := range siblings {
				if sibling.Alias == rel.Reference && sibling.Status == "queued" {
					log.Logger.Info("QueueProcessor: dependency not met, skipping",
						"resource", res.Name, "waitingFor", rel.Reference)
					return false
				}
			}
		}
	}

	// Find candidate clusters and try to reserve a rate-limit slot.
	clusters, err := a.GetSchedulableClusters(params.CloudSelector, params.ClusterRelation, nil, res.Alias)
	if err != nil {
		log.Logger.Error("QueueProcessor: error getting schedulable clusters",
			"error", err, "resource", res.Name)
		return false
	}

	// Apply cloud_preference to sort candidates by priority.
	// This matters because claimedClusters limits to one dequeue per
	// cluster per cycle — preferred clusters should be tried first.
	if len(params.CloudPreference) > 0 {
		clusters = ApplyPriorityWeight(clusters, params.CloudPreference, 1)
	}

	for _, cluster := range clusters {
		if claimedClusters[cluster.Name] {
			continue
		}

		if cluster.MaxPlacements != nil {
			currentCount, err := cluster.GetAccountCount()
			if err != nil {
				continue
			}
			if currentCount >= *cluster.MaxPlacements {
				continue
			}
		}

		rateLimited, err := res.CheckAndReserveSlot(&cluster)
		if err != nil {
			log.Logger.Error("QueueProcessor: error checking rate limit slot",
				"error", err, "cluster", cluster.Name, "resource", res.Name)
			continue
		}
		if !rateLimited {
			// Slot reserved. Mark all candidate clusters as claimed so the
			// next resource in the queue won't compete for the same slot.
			for _, c := range clusters {
				claimedClusters[c.Name] = true
			}
			return true
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// Queue processing: helpers
// ---------------------------------------------------------------------------

// stampQueueCheckedAt updates the queue_checked_at timestamp so the rescuer
// knows this resource was recently evaluated and can skip it.
func (a *OcpSandboxProvider) stampQueueCheckedAt(resourceID int, resourceName string) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := a.DbPool.Exec(context.Background(),
		`UPDATE resources
		 SET resource_data = jsonb_set(resource_data, '{queue_checked_at}', to_jsonb($2::text))
		 WHERE id = $1 AND status = 'queued'`,
		resourceID, now,
	); err != nil {
		log.Logger.Error("QueueProcessor: error stamping queue_checked_at",
			"error", err, "resource", resourceName)
	}
}

// casTransitionToInitializing atomically transitions a resource from "queued"
// to "initializing". Returns true if the transition succeeded. On failure,
// clears the slot reservation.
func (a *OcpSandboxProvider) casTransitionToInitializing(res OcpSandboxWithCreds) bool {
	ct, err := a.DbPool.Exec(context.Background(),
		`UPDATE resources
		 SET status = 'initializing',
		     resource_data = jsonb_set(resource_data, '{status}', '"initializing"')
		 WHERE id = $1 AND status = 'queued'`,
		res.ID,
	)
	if err != nil {
		log.Logger.Error("QueueProcessor: error transitioning resource",
			"error", err, "resource", res.Name)
		if err := res.reserveClusterSlot(""); err != nil {
			log.Logger.Error("QueueProcessor: error clearing slot reservation",
				"error", err, "resource", res.Name)
		}
		return false
	}
	if ct.RowsAffected() > 0 {
		log.Logger.Info("QueueProcessor: dequeuing resource",
			"resource", res.Name, "serviceUuid", res.ServiceUuid)
		metrics.QueueDequeueTotal.Inc()
		return true
	}
	// CAS missed — resource was already processed; clear the slot
	if err := res.reserveClusterSlot(""); err != nil {
		log.Logger.Error("QueueProcessor: error clearing slot reservation",
			"error", err, "resource", res.Name)
	}
	return false
}

// provisionDequeuedResource deletes the queued placeholder and re-calls
// Request() to create and provision a fresh resource. Preserves created_at
// on re-queue for FIFO ordering.
func (a *OcpSandboxProvider) provisionDequeuedResource(res OcpSandboxWithCreds) {
	params := res.QueuedParams
	if params == nil {
		log.Logger.Error("QueueProcessor: cannot provision resource without queued_params",
			"id", res.ID, "name", res.Name)
		return
	}

	serviceUuid := res.ServiceUuid
	annotations := res.Annotations
	alias := res.Alias
	noNamespace := res.NoNamespace

	// Delete the queued placeholder resource so Request() can create
	// a fresh one with the same service_uuid.
	if _, err := a.DbPool.Exec(context.Background(),
		"DELETE FROM resources WHERE id = $1", res.ID,
	); err != nil {
		log.Logger.Error("QueueProcessor: error deleting queued resource",
			"error", err, "id", res.ID)
		return
	}

	log.Logger.Info("QueueProcessor: provisioning dequeued resource",
		"name", res.Name, "serviceUuid", serviceUuid, "alias", alias)

	// Re-call Request() which creates a new resource and starts async provisioning.
	// If still rate-limited, Request() creates a new queued resource (will be
	// retried next cycle).
	originalCreatedAt := res.CreatedAt

	newRes, err := a.Request(
		serviceUuid,
		params.CloudSelector,
		params.CloudPreference,
		annotations,
		params.RequestedQuota,
		params.RequestedLimitRange,
		params.Multiple,
		context.Background(),
		alias,
		params.ClusterRelation,
		params.KeycloakUserPrefix,
		noNamespace,
	)
	if err != nil {
		log.Logger.Error("QueueProcessor: error re-requesting resource",
			"error", err, "serviceUuid", serviceUuid, "alias", alias)
		return
	}

	// If the resource was re-queued (rate limit still exhausted due to
	// timing), preserve the original created_at so FIFO ordering is
	// maintained. Without this, re-queued resources get a fresh timestamp
	// and lose their place in the queue.
	if newRes.Status == "queued" {
		if _, err := a.DbPool.Exec(context.Background(),
			"UPDATE resources SET created_at = $1 WHERE id = $2",
			originalCreatedAt, newRes.ID,
		); err != nil {
			log.Logger.Error("QueueProcessor: error preserving created_at for re-queued resource",
				"error", err, "id", newRes.ID)
		}
	}
}

// updateCompletedPlacements checks if any queued placements have all their
// resources provisioned and transitions them to "initializing".
func (a *OcpSandboxProvider) updateCompletedPlacements() {
	queuedPlacements, err := FetchQueuedPlacements(a.DbPool)
	if err != nil {
		log.Logger.Error("QueueProcessor: error fetching queued placements for completion check", "error", err)
		return
	}
	for _, p := range queuedPlacements {
		a.checkPlacementCompletion(p.ServiceUuid)
	}
}

// checkPlacementCompletion checks if all resources for a placement's
// service_uuid are done (no longer queued). If so, updates the placement
// status from "queued" to let the normal LoadActiveResources flow take over.
func (a *OcpSandboxProvider) checkPlacementCompletion(serviceUuid string) {
	var queuedCount int
	if err := a.DbPool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM resources
		 WHERE service_uuid = $1
		   AND resource_type = 'OcpSandbox'
		   AND status = 'queued'`,
		serviceUuid,
	).Scan(&queuedCount); err != nil {
		log.Logger.Error("QueueProcessor: error checking queued resource count",
			"error", err, "serviceUuid", serviceUuid)
		return
	}

	if queuedCount == 0 {
		// All resources are no longer queued — update placement status
		// to "initializing" so LoadActiveResources can manage it normally.
		ct, err := a.DbPool.Exec(
			context.Background(),
			"UPDATE placements SET status = 'initializing' WHERE service_uuid = $1 AND status = 'queued'",
			serviceUuid,
		)
		if err != nil {
			log.Logger.Error("QueueProcessor: error updating placement status",
				"error", err, "serviceUuid", serviceUuid)
		} else if ct.RowsAffected() > 0 {
			log.Logger.Info("QueueProcessor: all resources dequeued, placement status updated",
				"serviceUuid", serviceUuid)
		}
	}
}
