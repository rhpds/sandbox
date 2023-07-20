package models

import (
	"context"
	"errors"

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
	DbPool       *pgxpool.Pool `json:"dbpool,omitempty"`
	Result       Status        `json:"lifecycle_result,omitempty"`
}

type LifecyclePlacementJob struct {
	Model

	PlacementID int           `json:"placement_id"`
	Status      string        `json:"status"`
	Action      string        `json:"lifecycle_action"`
	Request     any           `json:"request,omitempty"`
	RequestID   string        `json:"request_id,omitempty"`
	DbPool      *pgxpool.Pool `json:"dbpool"`
}

// GetLifecycleResourceJob returns a LifecycleResourceJob by ID
func GetLifecycleResourceJob(dbpool *pgxpool.Pool, id int) (*LifecycleResourceJob, error) {
	var j LifecycleResourceJob

	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id, COALESCE(parent_id, 0), resource_name, resource_type, status, request, lifecycle_result, lifecycle_action, updated_at FROM lifecycle_resource_jobs WHERE id = $1",
		id,
	).Scan(&j.ID, &j.ParentID, &j.ResourceName, &j.ResourceType, &j.Status, &j.Request, &j.Result, &j.Action, &j.UpdatedAt)

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
		"SELECT id, COALESCE(parent_id, 0), resource_name, resource_type, status, request, lifecycle_result, lifecycle_action, updated_at FROM lifecycle_resource_jobs WHERE request_id = $1",
		requestID,
	).Scan(&j.ID, &j.ParentID, &j.ResourceName, &j.ResourceType, &j.Status, &j.Request, &j.Result, &j.Action, &j.UpdatedAt)

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
		"SELECT id, placement_id, status, request, lifecycle_action FROM lifecycle_placement_jobs WHERE id = $1",
		id,
	).Scan(&j.ID, &j.PlacementID, &j.Status, &j.Request, &j.Action)
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
		"SELECT id, placement_id, status, request, lifecycle_action FROM lifecycle_placement_jobs WHERE request_id = $1",
		requestID,
	).Scan(&j.ID, &j.PlacementID, &j.Status, &j.Request, &j.Action)
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
		`UPDATE lifecycle_resource_jobs SET status = 'initializing'
     	 WHERE id = (SELECT id FROM lifecycle_resource_jobs
         WHERE status = 'new' AND id=$1 FOR UPDATE SKIP LOCKED)`,
		j.ID,
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
		`UPDATE lifecycle_placement_jobs SET status = 'initializing'
     	 WHERE id = (SELECT id FROM lifecycle_placement_jobs
         WHERE status = 'new' AND id=$1 FOR UPDATE SKIP LOCKED)`,
		j.ID,
	)
	log.Logger.Info("Claiming placement job", "rows", ct.RowsAffected(), "err", err)
	if ct.RowsAffected() == 0 {
		return ErrNoClaim
	}

	if err != nil {
		return err
	}

	return nil
}

// Create creates a new LifecycleResourceJob by inserting it into the database
func (j *LifecycleResourceJob) Create() error {
	err := j.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO lifecycle_resource_jobs
        (parent_id, resource_name, resource_type, status, request, request_id, lifecycle_action)
        VALUES (NULLIF($1, 0), $2, $3, $4, $5, $6, $7) RETURNING id`,
		j.ParentID,
		j.ResourceName,
		j.ResourceType,
		j.Status,
		j.Request,
		j.RequestID,
		j.Action,
	).Scan(&j.ID)

	if err != nil {
		return err
	}

	return nil
}

// Create creates a new LifecyclePlacementJob by inserting it into the database
func (j *LifecyclePlacementJob) Create() error {
	err := j.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO lifecycle_placement_jobs
		(placement_id, status, request, request_id, lifecycle_action)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		j.PlacementID,
		j.Status,
		j.Request,
		j.RequestID,
		j.Action,
	).Scan(&j.ID)

	if err != nil {
		return err
	}
	return nil
}

// SetLifecycleResourceJobStatus sets the status of a LifecycleResourceJob
func (j *LifecycleResourceJob) SetStatus(status string) error {
	_, err := j.DbPool.Exec(
		context.Background(),
		"UPDATE lifecycle_resource_jobs SET status = $1 WHERE id = $2",
		status,
		j.ID,
	)

	if err != nil {
		return err
	}

	return nil
}

// SetLifecycleResourceJobStatus sets the status of a LifecycleResourceJob
func (j *LifecyclePlacementJob) SetStatus(status string) error {
	_, err := j.DbPool.Exec(
		context.Background(),
		"UPDATE lifecycle_placement_jobs SET status = $1 WHERE id = $2",
		status,
		j.ID,
	)

	if err != nil {
		return err
	}

	return nil
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
	for rows.Next() {
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

	if rows.Err() != nil {
		return "unknown", err
	}
	return status, nil
}