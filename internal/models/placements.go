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

	ServiceUuid string            `json:"service_uuid"`
	Resources   []any             `json:"resources,omitempty"`
	Annotations map[string]string `json:"annotations"`
	Request     any               `json:"request"`
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

func (p *Placement) LoadResources(accountProvider AwsAccountProvider) error {

	accounts, err := accountProvider.FetchAllByServiceUuid(p.ServiceUuid)

	if err != nil {
		return err
	}

	p.Resources = []any{}

	for _, account := range accounts {
		p.Resources = append(p.Resources, account)
	}

	return nil
}

func (p *Placement) LoadResourcesWithCreds(accountProvider AwsAccountProvider) error {

	accounts, err := accountProvider.FetchAllByServiceUuidWithCreds(p.ServiceUuid)

	if err != nil {
		return err
	}

	p.Resources = []any{}

	for _, account := range accounts {
		p.Resources = append(p.Resources, account)
	}

	return nil
}

func (p *Placement) LoadActiveResources(accountProvider AwsAccountProvider) error {
	accounts, err := accountProvider.FetchAllActiveByServiceUuid(p.ServiceUuid)

	if err != nil {
		return err
	}

	p.Resources = []any{}

	for _, account := range accounts {
		p.Resources = append(p.Resources, account)
	}

	return nil
}

func (p *Placement) LoadActiveResourcesWithCreds(accountProvider AwsAccountProvider) error {

	accounts, err := accountProvider.FetchAllActiveByServiceUuidWithCreds(p.ServiceUuid)

	if err != nil {
		return err
	}

	p.Resources = []any{}

	for _, account := range accounts {
		p.Resources = append(p.Resources, account)
	}

	return nil
}

func (p *Placement) Save(dbpool *pgxpool.Pool) error {
	var id int
	// Check if placement already exists in the DB
	err := dbpool.QueryRow(
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
		err = dbpool.QueryRow(
			context.Background(),
			"INSERT INTO placements (service_uuid, request, annotations) VALUES ($1, $2, $3) RETURNING id",
			p.ServiceUuid, p.Request, p.Annotations,
		).Scan(&id)

		if err != nil {
			return err
		}

		p.ID = id
		return nil
	}

	return nil
}

func (p *Placement) Delete(dbpool *pgxpool.Pool, accountProvider AwsAccountProvider) error {
	if p.ID == 0 {
		return errors.New("Placement ID is required")
	}

	if err := accountProvider.MarkForCleanupByServiceUuid(p.ServiceUuid); err != nil {
		return err
	}

	_, err := dbpool.Exec(
		context.Background(),
		"DELETE FROM placements WHERE id = $1", p.ID,
	)

	if err != nil {
		return err
	}

	// Mark all resources associated with this placement for cleanup
	// NOTE: This will done automatically by the SQL constraints when we move to Postgresql instead of
	// dynamodb for the accounts.

	p.LoadResources(accountProvider)

	return err
}

func (p *Placement) GetLastStatus(dbpool *pgxpool.Pool) ([]*LifecycleResourceJob, error) {
	var id int
	err := dbpool.QueryRow(
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

	rows, err := dbpool.Query(
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

		job, err := GetLifecycleResourceJob(dbpool, idR)

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
		"SELECT id, service_uuid, request, annotations, created_at, updated_at FROM placements WHERE id = $1", id,
	).Scan(&p.ID, &p.ServiceUuid, &p.Request, &p.Annotations, &p.CreatedAt, &p.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return &p, nil
}

// GetAllPlacements returns all placements

func GetAllPlacements(dbpool *pgxpool.Pool) (Placements, error) {
	rows, err := dbpool.Query(
		context.Background(),
		"SELECT id, service_uuid, request, annotations, created_at, updated_at FROM placements",
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var placements Placements

	for rows.Next() {
		var p Placement
		err := rows.Scan(&p.ID, &p.ServiceUuid, &p.Request, &p.Annotations, &p.CreatedAt, &p.UpdatedAt)
		if err != nil {
			return nil, err
		}
		placements = append(placements, p)
	}

	return placements, nil
}

// GetPlacementByServiceUuid returns a placement by service_uuid
func GetPlacementByServiceUuid(dbpool *pgxpool.Pool, serviceUuid string) (*Placement, error) {
	var p Placement

	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id, service_uuid, request, annotations, created_at, updated_at FROM placements WHERE service_uuid = $1", serviceUuid,
	).Scan(&p.ID, &p.ServiceUuid, &p.Request, &p.Annotations, &p.CreatedAt, &p.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return &p, nil
}

// DeletePlacementByServiceUuid deletes a placement by ServiceUuid
func DeletePlacementByServiceUuid(dbpool *pgxpool.Pool, accountProvider AwsAccountProvider, serviceUuid string) error {
	placement, err := GetPlacementByServiceUuid(dbpool, serviceUuid)
	if err != nil {
		return err
	}
	return placement.Delete(dbpool, accountProvider)
}
