package models

import (
	"context"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
)

type AuditEntry struct {
	ID         int64     `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Actor      string    `json:"actor"`
	Role       string    `json:"role"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	RequestID  string    `json:"request_id,omitempty"`
}

func InsertAuditEntry(dbpool *pgxpool.Pool, entry AuditEntry) error {
	_, err := dbpool.Exec(context.Background(), `
		INSERT INTO audit_log (actor, role, method, path, status_code, request_id)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		entry.Actor, entry.Role, entry.Method, entry.Path, entry.StatusCode, entry.RequestID)
	return err
}

// FetchAuditLogByActor returns the most recent audit log entries for a given actor.
func FetchAuditLogByActor(dbpool *pgxpool.Pool, actor string, limit int) ([]AuditEntry, error) {
	rows, err := dbpool.Query(context.Background(), `
		SELECT id, created_at, actor, role, method, path, status_code, COALESCE(request_id, '')
		FROM audit_log
		WHERE actor = $1
		ORDER BY created_at DESC
		LIMIT $2`, actor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Actor, &e.Role, &e.Method, &e.Path, &e.StatusCode, &e.RequestID); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}

	if entries == nil {
		entries = []AuditEntry{}
	}
	return entries, nil
}

// PurgeAuditLog deletes audit_log entries older than the given retention period.
// Returns the number of rows deleted.
func PurgeAuditLog(dbpool *pgxpool.Pool, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention)
	tag, err := dbpool.Exec(context.Background(), `
		DELETE FROM audit_log WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// StartAuditLogPurge runs a background goroutine that periodically purges
// old audit log entries. It runs once per day.
func StartAuditLogPurge(ctx context.Context, dbpool *pgxpool.Pool, retention time.Duration) {
	go func() {
		// Run initial purge on startup
		deleted, err := PurgeAuditLog(dbpool, retention)
		if err != nil {
			log.Logger.Error("AuditLogPurge: initial purge failed", "error", err)
		} else if deleted > 0 {
			log.Logger.Info("AuditLogPurge: initial purge", "deleted", deleted, "retention", retention)
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Logger.Info("AuditLogPurge: context cancelled, stopping")
				return
			case <-ticker.C:
				deleted, err := PurgeAuditLog(dbpool, retention)
				if err != nil {
					log.Logger.Error("AuditLogPurge: purge failed", "error", err)
				} else if deleted > 0 {
					log.Logger.Info("AuditLogPurge: purged old entries", "deleted", deleted, "retention", retention)
				}
			}
		}
	}()
}
