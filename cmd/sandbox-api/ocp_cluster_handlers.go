package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/go-chi/render"
)

func (h *BaseHandler) CreateOcpClusterHandler(w http.ResponseWriter, r *http.Request) {
	ocpCluster := &models.OcpCluster{}

	if err := render.Bind(r, ocpCluster); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	ocpCluster.DbPool = h.OcpAccountProvider.DbPool
	ocpCluster.VaultSecret = h.OcpAccountProvider.VaultSecret

	if err := ocpCluster.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to save OCP cluster",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP cluster created",
	})
}

// Disable an OCP cluster
func (h *BaseHandler) DisableOcpClusterHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP cluster from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP cluster from the database
	ocpCluster, err := h.OcpAccountProvider.GetOcpClusterByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP cluster not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP cluster",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Disable the OCP cluster
	if err := ocpCluster.Disable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to disable OCP cluster",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP cluster is disabled",
	})
}

// GetOcpClustersHandlers returns a list of OCP clusters
func (h *BaseHandler) GetOcpClustersHandler(w http.ResponseWriter, r *http.Request) {
	ocpClusters, err := h.OcpAccountProvider.GetOcpClusters()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP clusters",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &ocpClusters)
}

// GetOcpClusterHandler returns a single OCP cluster
func (h *BaseHandler) GetOcpClusterHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP cluster from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP cluster from the database
	ocpCluster, err := h.OcpAccountProvider.GetOcpClusterByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP cluster not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP cluster",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &ocpCluster)
}

// DeleteOcpClusterHandler deletes an OCP cluster
func (h *BaseHandler) DeleteOcpClusterHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP cluster from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP cluster from the database
	ocpCluster, err := h.OcpAccountProvider.GetOcpClusterByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP cluster not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP cluster",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	count, err := ocpCluster.GetAccountCount()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get account count",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	if count > 0 {
		w.WriteHeader(http.StatusConflict)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusConflict,
			Message:        "OCP cluster has accounts associated with it",
		})
		return
	}

	// Delete the OCP cluster
	if err := ocpCluster.Delete(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to delete OCP cluster",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP cluster deleted",
	})
}
