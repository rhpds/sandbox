package models

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/rhpds/sandbox/internal/log"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

type Reservation struct {
	Model

	Name    string             `json:"name"`
	Status  string             `json:"status"`
	Request ReservationRequest `json:"request"`
}

type ResourceRequest struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type ReservationRequest struct {
	Name      string            `json:"name"`
	Resources []ResourceRequest `json:"resources"`
}

func (r *ReservationRequest) Bind(r2 *http.Request) error {
	return nil
}

func (r *ReservationRequest) Validate(h AwsAccountProvider) (string, error) {
	done := make(map[string]bool)

	for _, resource := range r.Resources {
		if resource.Count < 1 {
			return "Count must be >= 1", errors.New("invalid count")
		}

		switch resource.Kind {
		case "AwsSandbox", "AwsAccount", "aws_account":
			// Ensure the kind is defined only once
			if _, ok := done["AwsSandbox"]; ok {
				return fmt.Sprintf("Kind AwsSandbox is defined more than once"), errors.New("invalid kind")
			}

			done["AwsSandbox"] = true

			// Get the current number of total and available accounts
			available, err := h.CountAvailable("")
			if err != nil {
				return "", err
			}
			total, err := h.Count()
			if err != nil {
				return "", err
			}

			// We don't want to allow a reservation that would put the total amount of
			// available accounts below 20% of the total amount of accounts.

			// formula:
			// Let x the maximal request count
			// (available - x) / total > 0.2
			// available - x >= total * 0.2
			// x <= available - total * 0.2
			max := available - int(float64(total)*0.2)
			// Validate Count
			if max <= 0 {
				log.Logger.Info(
					"Not enough available resources",
					"available", available,
					"total", total,
					"20% of total", int(float64(total)*0.2),
					"max", max)
				return "Not enough available resources", errors.New("not enough available resources")
			}

			if resource.Count > max {
				log.Logger.Info(
					"Not enough available resources",
					"available", available,
					"total", total,
					"20% of total", int(float64(total)*0.2),
					"max", max)
				return fmt.Sprintf("You can only reserve up to %d accounts", max), errors.New("not enough available resources")
			}

		default:
			return fmt.Sprintf("unsupported kind: %s", resource.Kind), errors.New("invalid kind")
		}
	}

	return "", nil
}

func (o *Reservation) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type Reservations []Reservation

func (o Reservations) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// Save saves a reservation to the database
// Reservations implies async operations.
// This function is low level and doesn't deal with async operations.
// For that, see the Initialize and Synchronize methods
func (r *Reservation) Save(dbpool *pgxpool.Pool) error {

	if r.ID != 0 {
		// UPDATE
		ct, err := dbpool.Exec(
			context.Background(),
			"UPDATE reservations SET reservation_name = $1, status = $2, request = $3 WHERE id = $4",
			r.Name, r.Status, r.Request, r.ID,
		)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			return errors.New("no rows affected")
		}

		return nil
	}

	var id int

	// Check if the reservation already exists
	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id FROM reservations WHERE reservation_name = $1",
		r.Name,
	).Scan(&id)

	if err != nil && err != pgx.ErrNoRows {
		return err
	}

	if id != 0 {
		r.ID = id
		ct, err := dbpool.Exec(
			context.Background(),
			"UPDATE reservations SET status = $1, request = $2 WHERE id = $3",
			r.Status, r.Request, r.ID,
		)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			return errors.New("no rows affected")
		}
		return nil
	}

	// New reservation we create it
	err = dbpool.QueryRow(
		context.Background(),
		"INSERT INTO reservations (reservation_name, status, request) VALUES ($1, $2, $3) RETURNING id",
		r.Name, r.Status, r.Request,
	).Scan(&id)

	if err != nil {
		return err
	}

	r.ID = id
	return nil
}

// Delete deletes a reservation from the DB
func (r *Reservation) Delete(dbpool *pgxpool.Pool) error {
	if r.ID == 0 {
		return errors.New("id is required")
	}

	_, err := dbpool.Exec(
		context.Background(),
		"DELETE FROM reservations WHERE id = $1",
		r.ID,
	)

	return err
}

// GetReservationByName fetches a reservation by its name
// returns the reservation and an error
func GetReservationByName(dbpool *pgxpool.Pool, name string) (*Reservation, error) {
	reservation := &Reservation{}

	err := dbpool.QueryRow(
		context.Background(),
		`SELECT id,
                reservation_name,
				status,
                request,
				created_at,
 				updated_at FROM reservations WHERE reservation_name = $1`,
		name,
	).Scan(
		&reservation.ID,
		&reservation.Name,
		&reservation.Status,
		&reservation.Request,
		&reservation.CreatedAt,
		&reservation.UpdatedAt,
	)

	return reservation, err
}

// UpdateStatus updates the status of a reservation
func (r *Reservation) UpdateStatus(dbpool *pgxpool.Pool, status string) error {
	log.Logger.Info("updating status", "status", status, "reservation", r)
	r.Status = status

	// Ensure id is set
	if r.ID == 0 {
		return errors.New("id is required")
	}

	_, err := dbpool.Exec(
		context.Background(),
		"UPDATE reservations SET status = $1 WHERE id = $2",
		r.Status, r.ID,
	)

	return err
}

// Initialize initializes a reservation
// It's an async operation that takes care of keeping the resources reserved Status up to date
// and also update the resources to match what's defined in Request.
// When everything is in sync, Status is set to 'success'
// If something goes wrong, Status is set to 'error'
func (r *Reservation) Initialize(dbpool *pgxpool.Pool, a AwsAccountProvider) {
	// At this point, the Request has been validated already using the
	// ReservationRequest.Validate method.
	// Also the reservation has been saved to the database and its status is 'initializing'

	// Loop through the Request.Resources and try to update the resources
	// and put some of them inside the new reservation
	for _, resource := range r.Request.Resources {
		switch resource.Kind {
		case "AwsSandbox", "AwsAccount", "aws_account":
			_, err := a.Reserve(r.Name, resource.Count)
			if err != nil {
				r.UpdateStatus(dbpool, "error")
				return
			}

			r.UpdateStatus(dbpool, "success")
		}
	}
}

// Delete deletes a reservation
// This is an async operation that goes through all the reserved resources
// and unmark them.
// Then the reservation is deleted from the DB if all goes well.
// If something goes wrong, the reservation is marked as 'error'
func (r *Reservation) Remove(dbpool *pgxpool.Pool, a AwsAccountProvider) {
	// Loop through the Request.Resources and try to update the resources
	// by removing the reservation.
	for _, resource := range r.Request.Resources {
		switch resource.Kind {
		case "AwsSandbox", "AwsAccount", "aws_account":
			if err := a.ScaleDownReservation(r.Name, 0); err != nil {
				r.UpdateStatus(dbpool, "error")
				return
			}

			if err := r.Delete(dbpool); err != nil {
				r.UpdateStatus(dbpool, "error")
				return
			}
		}
	}
}

// Update is an async operation to update a reservation from a reservationRequest
func (r *Reservation) Update(dbpool *pgxpool.Pool, a AwsAccountProvider, req ReservationRequest) {
	r.UpdateStatus(dbpool, "updating")
	// Loop through the Request.Resources and try to update the resources
	// by removing the reservation.
	for i, resource := range r.Request.Resources {
		for _, reqResource := range req.Resources {
			if reqResource.Kind == resource.Kind {
				// Determine if it's a scale up or a scale down
				if resource.Count <= reqResource.Count {
					// scale up
					if _, err := a.Reserve(r.Name, reqResource.Count); err != nil {
						r.UpdateStatus(dbpool, "error")
					} else {
						r.Request.Resources[i].Count = reqResource.Count
						r.Save(dbpool)
					}
				} else {
					// scale down
					if err := a.ScaleDownReservation(r.Name, reqResource.Count); err != nil {
						r.UpdateStatus(dbpool, "error")
					} else {
						r.Request.Resources[i].Count = reqResource.Count
						r.Save(dbpool)
					}
				}
			}
		}
	}
	r.UpdateStatus(dbpool, "success")
}

// Rename renames a reservation
// This is an async operation that goes through all the reserved resources
// and unmark them.
// Then the reservation is renamed in the DB if all goes well.
// If something goes wrong, the reservation is marked as 'error'
// and the name is not changed.
// The name must be unique.

func (r *Reservation) Rename(dbpool *pgxpool.Pool, a AwsAccountProvider, name string) {

	// Ensure id is set
	if r.ID == 0 {
		log.Logger.Error("rename reservation", "error", "id is required")
		return
	}

	r.UpdateStatus(dbpool, "updating")

	// Check if the new name is already taken
	var id int
	err := dbpool.QueryRow(
		context.Background(),
		"SELECT id FROM reservations WHERE reservation_name = $1",
		name,
	).Scan(&id)

	if err != nil && err != pgx.ErrNoRows {
		log.Logger.Error("rename reservation", "error", err)
		r.UpdateStatus(dbpool, "error")
		return
	}

	if id != 0 {
		log.Logger.Error("rename reservation", "error", "name already taken")
		return
	}

	if err := a.RenameReservation(r.Name, name); err != nil {
		log.Logger.Error("rename reservation", "error", err)
		r.UpdateStatus(dbpool, "error")
		return
	}

	r.Name = name
	r.Request.Name = name
	if err := r.Save(dbpool); err != nil {
		log.Logger.Error("rename reservation", "error", err)
		r.UpdateStatus(dbpool, "error")
		return
	}

	log.Logger.Info("rename reservation", "reservation", r)

	if err := r.UpdateStatus(dbpool, "success"); err != nil {
		log.Logger.Error("rename reservation, update status", "error", err)
	}
}
