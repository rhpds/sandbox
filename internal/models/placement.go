package models

import (
	"context"
	"errors"

	"github.com/rhpds/sandbox/internal/log"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"net/http"
)

type Placement struct {
	Model

	ServiceUuid string            `json:"service_uuid"`
	Resources   []any        `json:"resources"`
	Annotations map[string]string `json:"annotations"`
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
			"INSERT INTO placements (service_uuid, annotations) VALUES ($1, $2) RETURNING id",
			p.ServiceUuid, p.Annotations,
		).Scan(&id)

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

	// Mark all resources associated with this placement for cleanup
	// NOTE: This will done automatically by the SQL constraints when we move to Postgresql instead of
	// dynamodb for the accounts.

	p.LoadResources(accountProvider)

	return err
}

// GetPlacement returns a placement by ID
func GetPlacement(dbpool *pgxpool.Pool, id int) (*Placement, error) {
	var p Placement

	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id, service_uuid, annotations FROM placements WHERE id = $1", id,
	).Scan(&p.ID, &p.ServiceUuid, &p.Annotations)

	if err != nil {
		return nil, err
	}

	return &p, nil
}

// GetAllPlacements returns all placements

func GetAllPlacements(dbpool *pgxpool.Pool) (Placements, error) {
	rows, err := dbpool.Query(
		context.Background(),
		"SELECT id, service_uuid, annotations FROM placements",
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var placements Placements

	for rows.Next() {
		var p Placement
		err := rows.Scan(&p.ID, &p.ServiceUuid, &p.Annotations)
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
		"SELECT id, service_uuid, annotations FROM placements WHERE service_uuid = $1", serviceUuid,
	).Scan(&p.ID, &p.ServiceUuid, &p.Annotations)

	if err != nil {
		return nil, err
	}

	return &p, nil
}


// DeletePlacementByServiceUuid deletes a placement by ServiceUuid
func DeletePlacementByServiceUuid(dbpool *pgxpool.Pool, accountProvider  AwsAccountProvider, serviceUuid string) error {
	placement, err := GetPlacementByServiceUuid(dbpool, serviceUuid)
	if err != nil {
		return err
	}
	return placement.Delete(dbpool, accountProvider)
}
