package models

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/matoous/go-nanoid/v2"

	"github.com/rhpds/sandbox/internal/config"
	"github.com/rhpds/sandbox/internal/log"
)

// Generic job
type Job struct {
	Model

	RequestID   string         `json:"request_id,omitempty"`
	ParentJobID int            `json:"parent_job_id,omitempty"`
	PlacementID int            `json:"placement_id,omitempty"`
	Locality    string         `json:"locality,omitempty"`
	Status      string         `json:"status,omitempty"`
	JobType     string         `json:"job_type,omitempty"`
	Body        map[string]any `json:"body,omitempty"`
	CompletedAt time.Time      `json:"completed_at"`
}

type JobStore struct {
	DB *pgxpool.Pool `json:"-"`
}

func NewJobStore(db *pgxpool.Pool) *JobStore {
	return &JobStore{DB: db}
}

func (s *JobStore) GetJobByID(ctx context.Context, id int) (*Job, error) {
	var j Job
	err := s.DB.QueryRow(
		ctx,
		`SELECT id,
		request_id,
		COALESCE(placement_id, 0),
		locality,
		status,
		job_type,
		body,
		created_at,
		updated_at,
		COALESCE(completed_at, '1970-01-01T00:00:00Z')
		FROM jobs WHERE id = $1`,
		id,
	).Scan(&j.ID,
		&j.RequestID,
		&j.PlacementID,
		&j.Locality,
		&j.Status,
		&j.JobType,
		&j.Body,
		&j.CreatedAt,
		&j.UpdatedAt,
		&j.CompletedAt)

	if err != nil {
		return nil, err
	}

	return &j, nil
}

func (s *JobStore) GetJobByRequestID(ctx context.Context, requestID string) (*Job, error) {
	var j Job
	err := s.DB.QueryRow(
		ctx,
		`SELECT id,
		request_id,
		COALESCE(placement_id, 0),
		locality,
		status,
		job_type,
		body,
		created_at,
		updated_at,
		COALESCE(completed_at, '1970-01-01T00:00:00Z')
		FROM jobs WHERE request_id = $1`,
		requestID,
	).Scan(&j.ID,
		&j.RequestID,
		&j.PlacementID,
		&j.Locality,
		&j.Status,
		&j.JobType,
		&j.Body,
		&j.CreatedAt,
		&j.UpdatedAt,
		&j.CompletedAt)

	if err != nil {
		return nil, err
	}

	return &j, nil
}

func (s *JobStore) CreateJob(ctx context.Context, job *Job) error {
	// test job.Locality

	requestID, err := gonanoid.New()

	if err != nil {
		log.Logger.Error("Error generating request ID", "error", err)
		return err
	}

	job.RequestID = requestID

	if job.Locality == "" {
		job.Locality = config.LocalityID
	}

	job.Status = "initializing"

	err = s.DB.QueryRow(
		ctx,
		`INSERT INTO jobs
		(request_id, placement_id, parent_job_id, locality, status, job_type, body)
		VALUES ($1, NULLIF($2, 0), NULLIF($3, 0), $4, $5, $6, $7)
		RETURNING id`,
		job.RequestID,
		job.PlacementID,
		job.ParentJobID,
		job.Locality,
		job.Status,
		job.JobType,
		job.Body,
	).Scan(&job.ID)

	return err
}

func (s *JobStore) UpdateJob(ctx context.Context, job *Job) error {
	_, err := s.DB.Exec(
		ctx,
		`UPDATE jobs SET request_id = $1, placement_id = NULLIF($2, 0),
		parent_job_id= NULLIF($3, 0),
		locality = $4,
		status = $5,
		job_type = $6,
		body = $7,
		completed_at = $8
		WHERE id = $9`,
		job.RequestID,
		job.PlacementID,
		job.ParentJobID,
		job.Locality,
		job.Status,
		job.JobType,
		job.Body,
		job.CompletedAt,
		job.ID,
	)

	return err
}

// SaveJob saves a job to the database, creating it if it doesn't exist or updating it if it does.
func (s *JobStore) SaveJob(ctx context.Context, job *Job) error {
	existingJob, err := s.GetJobByID(ctx, job.ID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return s.CreateJob(ctx, job)
		}
		return err
	}

	job.ID = existingJob.ID // Ensure we update the existing job
	return s.UpdateJob(ctx, job)
}

// DeleteJob deletes a job from the database by its ID.
func (s *JobStore) DeleteJob(ctx context.Context, id int) error {
	_, err := s.DB.Exec(
		ctx,
		`DELETE FROM jobs WHERE id = $1`,
		id,
	)
	return err
}

// SetJobStatus updates the status of a job in the database.
func (s *JobStore) SetJobStatus(ctx context.Context, job *Job, status string) error {
	if job == nil {
		return fmt.Errorf("job cannot be nil")
	}

	job.Status = status

	_, err := s.DB.Exec(
		ctx,
		`UPDATE jobs SET status = $1 WHERE id = $2`,
		status,
		job.ID,
	)

	return err
}

// GetJobsByType retrieves all jobs of a specific type from the database.
func (s *JobStore) GetJobsByType(ctx context.Context, jobType string) ([]*Job, error) {
	rows, err := s.DB.Query(
		ctx,
		`SELECT id,
		request_id,
		COALESCE(placement_id, 0),
		COALESCE(parent_job_id, 0),
		locality,
		status,
		job_type,
		body,
		created_at,
		updated_at,
		COALESCE(completed_at, '1970-01-01T00:00:00Z')
		FROM jobs WHERE job_type = $1`,
		jobType,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(
			&j.ID,
			&j.RequestID,
			&j.PlacementID,
			&j.ParentJobID,
			&j.Locality,
			&j.Status,
			&j.JobType,
			&j.Body,
			&j.CreatedAt,
			&j.UpdatedAt,
			&j.CompletedAt,
		); err != nil {
			return nil, err
		}
		jobs = append(jobs, &j)
	}

	return jobs, nil
}

func (s *JobStore) GetLatestJobByType(ctx context.Context, jobType string) (*Job, error) {
	rows, err := s.DB.Query(
		ctx,
		`SELECT id,
		request_id,
		COALESCE(placement_id, 0),
		COALESCE(parent_job_id, 0),
		locality,
		status,
		job_type,
		body,
		created_at,
		updated_at,
		COALESCE(completed_at, '1970-01-01T00:00:00Z')
		FROM jobs WHERE job_type = $1 ORDER BY created_at DESC LIMIT 1`,
		jobType,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, fmt.Errorf("no job found for type")
	}

	var j Job
	if err := rows.Scan(
		&j.ID,
		&j.RequestID,
		&j.PlacementID,
		&j.ParentJobID,
		&j.Locality,
		&j.Status,
		&j.JobType,
		&j.Body,
		&j.CreatedAt,
		&j.UpdatedAt,
		&j.CompletedAt,
	); err != nil {
		return nil, err
	}

	return &j, nil
}

func (t *Job) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// SetJobBody is a generic function that takes any struct 'T'
// and sets it as the job's body in the map[string]any format.
func SetJobBody[T any](job *Job, details T) error {
	bodyBytes, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("failed to marshal details struct: %w", err)
	}

	var bodyMap map[string]any
	if err := json.Unmarshal(bodyBytes, &bodyMap); err != nil {
		return fmt.Errorf("failed to unmarshal into map: %w", err)
	}

	job.Body = bodyMap
	return nil
}

// GetJobBody is a generic function that can parse any body type 'T'.
func GetJobBody[T any](job Job) (T, error) {
	var details T

	// Marshal the generic map from the job body into JSON bytes.
	bodyBytes, err := json.Marshal(job.Body)
	if err != nil {
		return details, fmt.Errorf("failed to marshal job body: %w", err)
	}

	// Unmarshal the JSON bytes into the specific struct 'T'.
	// This will correctly use custom UnmarshalJSON methods (like for resource.Quantity).
	if err := json.Unmarshal(bodyBytes, &details); err != nil {
		return details, fmt.Errorf("failed to unmarshal into target struct: %w", err)
	}

	return details, nil
}
