package models

import (
	"context"
	"errors"
	"time"

	"github.com/rhpds/sandbox/internal/config"
	"github.com/rhpds/sandbox/internal/log"

	"github.com/jackc/pgx/v4/pgxpool"
)

type LifecycleResourceJob struct {
	Model

	ResourceName string        `json:"resource_name"`
	ResourceType string        `json:"resource_type"`
	ParentID     int           `json:"parent_id,omitempty"`
	Status       string        `json:"status"`
	Action       string        `json:"lifecycle_action"`
	Request      any           `json:"request,omitempty"`
	RequestID    string        `json:"request_id,omitempty"`
	DbPool       *pgxpool.Pool `json:"-"`
	Result       Status        `json:"lifecycle_result,omitempty"`
	Locality     string        `json:"locality,omitempty"`
}

type LifecyclePlacementJob struct {
	Model

	PlacementID int           `json:"placement_id"`
	Status      string        `json:"status"`
	Action      string        `json:"lifecycle_action"`
	Request     any           `json:"request,omitempty"`
	RequestID   string        `json:"request_id,omitempty"`
	DbPool      *pgxpool.Pool `json:"-"`
	Locality    string        `json:"locality,omitempty"`
}

// GetLifecycleResourceJob returns a LifecycleResourceJob by ID
func GetLifecycleResourceJob(dbpool *pgxpool.Pool, id int) (*LifecycleResourceJob, error) {
	var j LifecycleResourceJob

	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id, COALESCE(parent_id, 0), resource_name, resource_type, status, request_id, request, lifecycle_result, lifecycle_action, updated_at, locality FROM lifecycle_resource_jobs WHERE id = $1",
		id,
	).Scan(&j.ID, &j.ParentID, &j.ResourceName, &j.ResourceType, &j.Status, &j.RequestID, &j.Request, &j.Result, &j.Action, &j.UpdatedAt, &j.Locality)

	if err != nil {
		return nil, err
	}

	j.DbPool = dbpool

	return &j, nil
}

func GetLifecycleResourceJobByRequestID(dbpool *pgxpool.Pool, requestID string) (*LifecycleResourceJob, error) {
	var j LifecycleResourceJob

	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id, COALESCE(parent_id, 0), resource_name, resource_type, status, request, lifecycle_result, lifecycle_action, updated_at, locality FROM lifecycle_resource_jobs WHERE request_id = $1",
		requestID,
	).Scan(&j.ID, &j.ParentID, &j.ResourceName, &j.ResourceType, &j.Status, &j.Request, &j.Result, &j.Action, &j.UpdatedAt, &j.Locality)

	if err != nil {
		return nil, err
	}

	j.DbPool = dbpool

	return &j, nil
}

// GetLifecyclePlacementJob returns a LifecyclePlacementJob by ID
func GetLifecyclePlacementJob(dbpool *pgxpool.Pool, id int) (*LifecyclePlacementJob, error) {
	var j LifecyclePlacementJob

	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id, placement_id, status, request_id, request, lifecycle_action, locality FROM lifecycle_placement_jobs WHERE id = $1",
		id,
	).Scan(&j.ID, &j.PlacementID, &j.Status, &j.RequestID, &j.Request, &j.Action, &j.Locality)
	if err != nil {
		return nil, err
	}

	j.DbPool = dbpool

	return &j, nil
}

// GetLifecyclePlacementJob returns a LifecyclePlacementJob by ID
func GetLifecyclePlacementJobByRequestID(dbpool *pgxpool.Pool, requestID string) (*LifecyclePlacementJob, error) {
	var j LifecyclePlacementJob

	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id, placement_id, status, request_id, request, lifecycle_action, locality FROM lifecycle_placement_jobs WHERE request_id = $1",
		requestID,
	).Scan(&j.ID, &j.PlacementID, &j.Status, &j.RequestID, &j.Request, &j.Action, &j.Locality)
	if err != nil {
		return nil, err
	}

	j.DbPool = dbpool

	return &j, nil
}

var ErrNoClaim = errors.New("no claim")

// ClaimResourceJob claims a resource job by setting the status to initializing
func (j *LifecycleResourceJob) Claim() error {
	ct, err := j.DbPool.Exec(
		context.Background(),
		`UPDATE lifecycle_resource_jobs SET status = 'initializing', locality = $2
     	 WHERE id = (SELECT id FROM lifecycle_resource_jobs
         WHERE status = 'new' AND id=$1 FOR UPDATE SKIP LOCKED)`,
		j.ID,
		config.LocalityID,
	)

	if ct.RowsAffected() == 0 {
		return ErrNoClaim
	}

	if err != nil {
		return err
	}

	return nil
}

// ClaimPlacementJob claims a placement job by setting the status to initializing
func (j *LifecyclePlacementJob) Claim() error {
	ct, err := j.DbPool.Exec(
		context.Background(),
		`UPDATE lifecycle_placement_jobs SET status = 'initializing', locality = $2
     	 WHERE id = (SELECT id FROM lifecycle_placement_jobs
         WHERE status = 'new' AND id=$1 FOR UPDATE SKIP LOCKED)`,
		j.ID,
		config.LocalityID,
	)
	log.Logger.Info("Claiming placement job", "rows", ct.RowsAffected(), "err", err)
	if ct.RowsAffected() == 0 {
		return ErrNoClaim
	}

	return err
}

// Create creates a new LifecycleResourceJob by inserting it into the database
func (j *LifecycleResourceJob) Create() error {
	err := j.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO lifecycle_resource_jobs
        (parent_id, resource_name, resource_type, status, request, request_id, lifecycle_action, locality)
        VALUES (NULLIF($1, 0), $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		j.ParentID,
		j.ResourceName,
		j.ResourceType,
		j.Status,
		j.Request,
		j.RequestID,
		j.Action,
		j.Locality,
	).Scan(&j.ID)

	return err
}

// Create creates a new LifecyclePlacementJob by inserting it into the database
func (j *LifecyclePlacementJob) Create() error {
	err := j.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO lifecycle_placement_jobs
		(placement_id, status, request, request_id, lifecycle_action, locality)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		j.PlacementID,
		j.Status,
		j.Request,
		j.RequestID,
		j.Action,
		j.Locality,
	).Scan(&j.ID)

	return err
}

// SetLifecycleResourceJobStatus sets the status of a LifecycleResourceJob
func (j *LifecycleResourceJob) SetStatus(status string) error {
	_, err := j.DbPool.Exec(
		context.Background(),
		"UPDATE lifecycle_resource_jobs SET status = $1 WHERE id = $2",
		status,
		j.ID,
	)

	return err
}

// SetLifecycleResourceJobStatus sets the status of a LifecycleResourceJob
func (j *LifecyclePlacementJob) SetStatus(status string) error {
	_, err := j.DbPool.Exec(
		context.Background(),
		"UPDATE lifecycle_placement_jobs SET status = $1 WHERE id = $2",
		status,
		j.ID,
	)

	return err
}

// GlobalStatus returns the status of a LifecyclePlacementJob considering all it's children
func (j *LifecyclePlacementJob) GlobalStatus() (string, error) {

	if j.Status != "successfully_dispatched" {
		return j.Status, nil
	}

	rows, err := j.DbPool.Query(
		context.TODO(),
		`SELECT id FROM lifecycle_resource_jobs
         WHERE parent_id = $1
         ORDER BY updated_at`,
		j.ID,
	)

	if err != nil {
		return "unknown", err
	}

	defer rows.Close()

	status := "unknown"
	count := 0
	for rows.Next() {
		count++
		var idR int
		err := rows.Scan(&idR)
		if err != nil {
			return "unknown", err
		}

		job, err := GetLifecycleResourceJob(j.DbPool, idR)

		if err != nil {
			return "unknown", err
		}

		switch job.Status {
		case "error":
			return "error", nil
		case "new":
			return "new", nil
		case "running":
			return "running", nil
		case "initializing":
			return "initializing", nil
		case "initialized":
			return "initialized", nil
		case "success":
			// Save as the last status and move to the next job
			status = "success"
		}
	}

	// If no rows are found, return success
	// This is a special case where resources lifecycle jobs are not implemented yet
	if count == 0 {
		return "success", nil
	}

	if rows.Err() != nil {
		log.Logger.Error("Error iterating over rows", "err", rows.Err())
		return "unknown", err
	}
	return status, nil
}

// AggregateLifecycleResults returns the aggregated lifecycle_result from all child resource jobs
func (j *LifecyclePlacementJob) AggregateLifecycleResults() (Status, error) {
	aggregated := Status{
		AwsInstances: []AwsInstance{},
		OcpResources: []OcpResource{},
	}

	rows, err := j.DbPool.Query(
		context.TODO(),
		`SELECT id FROM lifecycle_resource_jobs
         WHERE parent_id = $1
         ORDER BY updated_at`,
		j.ID,
	)

	if err != nil {
		return aggregated, err
	}

	defer rows.Close()

	var latestUpdatedAt time.Time

	for rows.Next() {
		var idR int
		err := rows.Scan(&idR)
		if err != nil {
			return aggregated, err
		}

		job, err := GetLifecycleResourceJob(j.DbPool, idR)
		if err != nil {
			return aggregated, err
		}

		// Track the latest updated_at from child jobs
		if job.UpdatedAt.After(latestUpdatedAt) {
			latestUpdatedAt = job.UpdatedAt
		}

		// Set the account info from the first job (they should all have the same placement)
		if aggregated.AccountName == "" {
			aggregated.AccountName = job.ResourceName
			aggregated.AccountKind = job.ResourceType
		}

		// Append AWS instances from child job's result
		if job.Result.AwsInstances != nil {
			aggregated.AwsInstances = append(aggregated.AwsInstances, job.Result.AwsInstances...)
		}

		// Append OCP resources from child job's result
		if job.Result.OcpResources != nil {
			aggregated.OcpResources = append(aggregated.OcpResources, job.Result.OcpResources...)
		}
	}

	if rows.Err() != nil {
		log.Logger.Error("Error iterating over rows for aggregation", "err", rows.Err())
		return aggregated, rows.Err()
	}

	// Set UpdatedAt to the latest from child jobs, or now if no children
	if latestUpdatedAt.IsZero() {
		aggregated.UpdatedAt = time.Now()
	} else {
		aggregated.UpdatedAt = latestUpdatedAt
	}

	return aggregated, nil
}
