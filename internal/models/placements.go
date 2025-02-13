package models

import (
	"context"
	"errors"
	"net/http"

	"github.com/rhpds/sandbox/internal/log"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

type Placement struct {
	Model

	ServiceUuid  string            `json:"service_uuid"`
	Status       string            `json:"status"`
	ToCleanup    bool              `json:"to_cleanup"`
	Annotations  map[string]string `json:"annotations"`
	Resources    []any             `json:"resources,omitempty"`
	Request      any               `json:"request"`
	DbPool       *pgxpool.Pool     `json:"-"`
	FailOnDelete bool              `json:"-"` // plumbing for testing
}

type PlacementWithCreds struct {
	Placement

	Resources []any `json:"resources"`
}

type Placements []Placement

func (p Placements) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *Placement) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *Placement) LoadResources(awsProvider AwsAccountProvider, ocpProvider OcpSandboxProvider, ibmProvider IBMResourceGroupSandboxProvider) error {

	accounts, err := awsProvider.FetchAllByServiceUuid(p.ServiceUuid)

	if err != nil {
		return err
	}

	p.Resources = []any{}

	for _, account := range accounts {
		p.Resources = append(p.Resources, account)
	}

	// AwsAccounts are always ready
	status := "success"

	ocpSandboxes, err := ocpProvider.FetchAllByServiceUuid(p.ServiceUuid)

	if err != nil {
		return err
	}

	for _, account := range ocpSandboxes {
		p.Resources = append(p.Resources, account)
		if account.Status != "success" {
			// update final status only if it's not already an error
			// propagate the status of the first error
			if status != "error" {
				status = account.Status
			}
		}
	}

	// If the placement is already an error, don't update the status
	// If the placement is deleting, don't update the status here neither
	if p.Status != "error" && p.Status != "deleting" {
		if err := p.SetStatus(status); err != nil {
			return err
		}
	}

	ibmSandboxes, err := ibmProvider.FetchAllByServiceUuid(p.ServiceUuid)

	if err != nil {
		return err
	}

	for _, account := range ibmSandboxes {
		p.Resources = append(p.Resources, account)
		if account.Status != "success" {
			// update final status only if it's not already an error
			// propagate the status of the first error
			if status != "error" {
				status = account.Status
			}
		}
	}

	// If the placement is already an error, don't update the status
	// If the placement is deleting, don't update the status here neither
	if p.Status != "error" && p.Status != "deleting" {
		if err := p.SetStatus(status); err != nil {
			return err
		}
	}

	return nil
}

func (p *Placement) LoadResourcesWithCreds(awsProvider AwsAccountProvider, ocpProvider OcpSandboxProvider, ibmProvider IBMResourceGroupSandboxProvider) error {

	accounts, err := awsProvider.FetchAllByServiceUuidWithCreds(p.ServiceUuid)

	if err != nil {
		return err
	}

	p.Resources = []any{}

	for _, account := range accounts {
		p.Resources = append(p.Resources, account)
	}
	// AwsAccounts are always ready
	status := "success"

	ocpSandboxes, err := ocpProvider.FetchAllByServiceUuidWithCreds(p.ServiceUuid)

	if err != nil {
		return err
	}

	for _, account := range ocpSandboxes {
		p.Resources = append(p.Resources, account)
		if account.Status != "success" {
			// update final status only if it's not already an error
			// propagate the status of the first error
			if status != "error" {
				status = account.Status
			}
		}
	}

	// If the placement is already an error, don't update the status
	// If the placement is deleting, don't update the status here neither
	if p.Status != "error" && p.Status != "deleting" {
		if err := p.SetStatus(status); err != nil {
			return err
		}
	}

	return nil
}

func (p *Placement) LoadActiveResources(awsProvider AwsAccountProvider) error {
	accounts, err := awsProvider.FetchAllActiveByServiceUuid(p.ServiceUuid)

	if err != nil {
		return err
	}

	p.Resources = []any{}

	for _, account := range accounts {
		p.Resources = append(p.Resources, account)
	}

	return nil
}

func (p *Placement) LoadActiveResourcesWithCreds(awsProvider AwsAccountProvider, ocpProvider OcpSandboxProvider, ibmProvider IBMResourceGroupSandboxProvider) error {

	accounts, err := awsProvider.FetchAllActiveByServiceUuidWithCreds(p.ServiceUuid)

	if err != nil {
		return err
	}

	p.Resources = []any{}

	for _, account := range accounts {
		p.Resources = append(p.Resources, account)
	}
	// AwsAccounts are always ready
	status := "success"

	ocpSandboxes, err := ocpProvider.FetchAllByServiceUuidWithCreds(p.ServiceUuid)

	if err != nil {
		return err
	}

	for _, account := range ocpSandboxes {
		p.Resources = append(p.Resources, account)
		if account.Status != "success" {
			// update final status only if it's not already an error
			// propagate the status of the first error
			if status != "error" {
				status = account.Status
			}
		}
	}

	ibmSandboxes, err := ibmProvider.FetchAllByServiceUuidWithCreds(p.ServiceUuid)

	if err != nil {
		return err
	}

	for _, account := range ibmSandboxes {
		p.Resources = append(p.Resources, account)
		if account.Status != "success" {
			// update final status only if it's not already an error
			// propagate the status of the first error
			if status != "error" {
				status = account.Status
			}
		}
	}

	// If the placement is already an error, don't update the status
	// If the placement is deleting, don't update the status here neither
	if p.Status != "error" && p.Status != "deleting" {
		if err := p.SetStatus(status); err != nil {
			return err
		}
	}
	return nil
}

func (p *Placement) Create() error {
	var id int
	// Check if placement already exists in the DB
	err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT id FROM placements WHERE service_uuid = $1", p.ServiceUuid,
	).Scan(&id)

	if err == nil {
		log.Logger.Error("Placement already exists", "id", id)
		return errors.New("Placement already exists")
	}

	if err != pgx.ErrNoRows {
		return err
	}

	if err == pgx.ErrNoRows {
		// Insert placement
		err = p.DbPool.QueryRow(
			context.Background(),
			`INSERT INTO placements
			 (service_uuid, request, annotations)
			 VALUES ($1, $2, $3) RETURNING id`,
			p.ServiceUuid, p.Request, p.Annotations,
		).Scan(&id)

		if err != nil {
			return err
		}

		p.ID = id

		// Update 'resources' table and set resources.placement_id to placements.id using the matching service UUID
		if _, err = p.DbPool.Exec(
			context.Background(),
			"UPDATE resources SET placement_id = $1 WHERE service_uuid = $2", p.ID, p.ServiceUuid,
		); err != nil {
			return err
		}

		return nil
	}

	return nil
}

// Delete deletes a placement
func (p *Placement) Delete(accountProvider AwsAccountProvider, ocpProvider OcpSandboxProvider, ibmProvider IBMResourceGroupSandboxProvider) {
	if err := p.SetStatus("deleting"); err != nil {
		log.Logger.Error("error setting status for placement",
			"serviceUuid", p.ServiceUuid,
			"error", err,
		)
		return
	}
	if p.FailOnDelete {
		log.Logger.Error("Failing on delete", "serviceUuid", p.ServiceUuid)
		p.SetStatus("error")
		return
	}

	if err := accountProvider.MarkForCleanupByServiceUuid(p.ServiceUuid); err != nil {
		log.Logger.Error("Error while releasing AWS sandboxes")
		p.SetStatus("error")
		return
	}

	if err := ocpProvider.Release(p.ServiceUuid); err != nil {
		log.Logger.Error("Error while releasing OCP sandboxes", "error", err)
		p.SetStatus("error")
		return
	}

	if err := ibmProvider.Release(p.ServiceUuid); err != nil {
		log.Logger.Error("Error while releasing IBMResourceGroup sandboxes", "error", err)
		p.SetStatus("error")
		return
	}

	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM placements WHERE id = $1", p.ID,
	)

	if err != nil {
		p.SetStatus("error")
		return
	}

	// Mark all resources associated with this placement for cleanup
	// NOTE: This will done automatically by the SQL constraints when we move to Postgresql instead of
	// dynamodb for the accounts.

	if err := p.LoadResources(accountProvider, ocpProvider, ibmProvider); err != nil {
		log.Logger.Error("Error loading resources",
			"serviceUuid", p.ServiceUuid,
			"error", err,
		)
		p.SetStatus("error")
		return
	}
}

func (p *Placement) GetLastStatus() ([]*LifecycleResourceJob, error) {
	var id int
	err := p.DbPool.QueryRow(
		context.TODO(),
		`SELECT id FROM lifecycle_placement_jobs
		 WHERE lifecycle_action = 'status'
		 AND status = 'successfully_dispatched'
		 AND placement_id = $1
		 ORDER BY updated_at DESC LIMIT 1`,
		p.ID,
	).Scan(&id)

	if err != nil {
		return nil, err
	}

	rows, err := p.DbPool.Query(
		context.TODO(),
		`SELECT id FROM lifecycle_resource_jobs
		 WHERE lifecycle_action = 'status'
		 AND parent_id = $1
		 ORDER BY updated_at`,
		id,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	result := []*LifecycleResourceJob{}

	for rows.Next() {
		var idR int
		err := rows.Scan(&idR)
		if err != nil {
			return nil, err
		}

		job, err := GetLifecycleResourceJob(p.DbPool, idR)

		if err != nil {
			return result, err
		}

		result = append(result, job)
	}

	if rows.Err() != nil {
		return result, err
	}

	return result, nil
}

// GetPlacement returns a placement by ID
func GetPlacement(dbpool *pgxpool.Pool, id int) (*Placement, error) {
	var p Placement

	err := dbpool.QueryRow(
		context.Background(),
		`SELECT
			id,
			service_uuid,
			request,
			annotations,
			status,
			to_cleanup,
			created_at,
			updated_at
		FROM placements WHERE id = $1`,
		id,
	).Scan(
		&p.ID,
		&p.ServiceUuid,
		&p.Request,
		&p.Annotations,
		&p.Status,
		&p.ToCleanup,
		&p.CreatedAt,
		&p.UpdatedAt)

	if err != nil {
		return nil, err
	}

	p.DbPool = dbpool

	return &p, nil
}

// GetAllPlacements returns all placements

func GetAllPlacements(dbpool *pgxpool.Pool) (Placements, error) {
	rows, err := dbpool.Query(
		context.Background(),
		`SELECT
			id,
			service_uuid,
			request,
			annotations,
			status,
			to_cleanup,
			created_at,
			updated_at
		FROM placements`,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var placements Placements

	for rows.Next() {
		var p Placement
		err := rows.Scan(
			&p.ID,
			&p.ServiceUuid,
			&p.Request,
			&p.Annotations,
			&p.Status,
			&p.ToCleanup,
			&p.CreatedAt,
			&p.UpdatedAt)
		if err != nil {
			return nil, err
		}
		p.DbPool = dbpool
		placements = append(placements, p)
	}

	return placements, nil
}

// GetPlacementByServiceUuid returns a placement by service_uuid
func GetPlacementByServiceUuid(dbpool *pgxpool.Pool, serviceUuid string) (*Placement, error) {
	var p Placement

	log.Logger.Info("GetPlacementByServiceUuid", "serviceUuid", serviceUuid)
	err := dbpool.QueryRow(
		context.Background(),
		`SELECT
			id,
			service_uuid,
			request,
			annotations,
			status,
			to_cleanup,
			created_at,
			updated_at
		FROM
		placements
		WHERE service_uuid = $1`,
		serviceUuid,
	).Scan(
		&p.ID,
		&p.ServiceUuid,
		&p.Request,
		&p.Annotations,
		&p.Status,
		&p.ToCleanup,
		&p.CreatedAt,
		&p.UpdatedAt)

	if err != nil {
		return nil, err
	}

	p.DbPool = dbpool
	return &p, nil
}

// DeletePlacementByServiceUuid deletes a placement by ServiceUuid
func DeletePlacementByServiceUuid(dbpool *pgxpool.Pool, awsProvider AwsAccountProvider, ocpProvider OcpSandboxProvider, ibmProvider IBMResourceGroupSandboxProvider, serviceUuid string) error {
	placement, err := GetPlacementByServiceUuid(dbpool, serviceUuid)
	if err != nil {
		return err
	}
	if placement.ID == 0 {
		return errors.New("Placement ID is required")
	}

	if err := placement.MarkForCleanup(); err != nil {
		return err
	}

	go placement.Delete(awsProvider, ocpProvider, ibmProvider)
	return nil
}

// SetStatus sets the status of a placement
func (p *Placement) SetStatus(status string) error {
	_, err := p.DbPool.Exec(
		context.Background(),
		"UPDATE placements SET status = $1 WHERE id = $2",
		status,
		p.ID,
	)

	if err != nil {
		log.Logger.Error("Error setting status", "error", err)
		return err
	}

	p.Status = status

	return nil
}

func (p *Placement) MarkForCleanup() error {
	_, err := p.DbPool.Exec(
		context.Background(),
		"UPDATE placements SET to_cleanup = true WHERE id = $1",
		p.ID,
	)

	if err != nil {
		return err
	}
	p.ToCleanup = true
	return nil
}
