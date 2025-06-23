package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/go-chi/render"
)

func (h *BaseHandler) CreateOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	ocpSharedClusterConfiguration := models.MakeOcpSharedClusterConfiguration()

	if err := render.Bind(r, ocpSharedClusterConfiguration); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	ocpSharedClusterConfiguration.DbPool = h.OcpSandboxProvider.DbPool
	ocpSharedClusterConfiguration.VaultSecret = h.OcpSandboxProvider.VaultSecret

	if err := ocpSharedClusterConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to save OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP shared cluster configuration created",
	})
}

// Disable an OCP shared cluster configuration
func (h *BaseHandler) DisableOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP shared cluster configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP shared cluster configuration from the database
	ocpSharedClusterConfiguration, err := h.OcpSandboxProvider.GetOcpSharedClusterConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP shared cluster configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Disable the OCP shared cluster configuration
	if err := ocpSharedClusterConfiguration.Disable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to disable OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP shared cluster configuration is disabled",
	})
}

func (h *BaseHandler) HealthOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP shared cluster configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP shared cluster configuration from the database
	cluster, err := h.OcpSandboxProvider.GetOcpSharedClusterConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP shared cluster configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	err = cluster.TestConnection()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Error connecting to OpenShift Cluster",
			ErrorMultiline: []string{err.Error()},
		})
	}

	w.WriteHeader(http.StatusOK)
}
func (h *BaseHandler) EnableOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP shared cluster configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP shared cluster configuration from the database
	ocpSharedClusterConfiguration, err := h.OcpSandboxProvider.GetOcpSharedClusterConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP shared cluster configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Enable the OCP shared cluster configuration
	if err := ocpSharedClusterConfiguration.Enable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to enable OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP shared cluster configuration is enabled",
	})
}

// GetOcpSharedClusterConfigurationsHandlers returns a list of OCP shared cluster configurations
func (h *BaseHandler) GetOcpSharedClusterConfigurationsHandler(w http.ResponseWriter, r *http.Request) {
	ocpSharedClusterConfigurations, err := h.OcpSandboxProvider.GetOcpSharedClusterConfigurations()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP shared cluster configurations",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &ocpSharedClusterConfigurations)
}

// GetOcpSharedClusterConfigurationHandler returns a single OCP shared cluster configuration
func (h *BaseHandler) GetOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP shared cluster configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP shared cluster configuration from the database
	ocpSharedClusterConfiguration, err := h.OcpSandboxProvider.GetOcpSharedClusterConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP shared cluster configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &ocpSharedClusterConfiguration)
}

// DeleteOcpSharedClusterConfigurationHandler deletes an OCP shared cluster configuration
func (h *BaseHandler) DeleteOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP shared cluster configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP shared cluster configuration from the database
	ocpSharedClusterConfiguration, err := h.OcpSandboxProvider.GetOcpSharedClusterConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP shared cluster configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	count, err := ocpSharedClusterConfiguration.GetAccountCount()
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
			Message:        "OCP shared cluster configuration has accounts associated with it",
		})
		return
	}

	// Delete the OCP shared cluster configuration
	if err := ocpSharedClusterConfiguration.Delete(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to delete OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP shared cluster configuration deleted",
	})
}

func (h *BaseHandler) UpdateOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the OCP shared cluster configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the OCP shared cluster configuration from the database
	ocpSharedClusterConfiguration, err := h.OcpSandboxProvider.GetOcpSharedClusterConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "OCP shared cluster configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// unmarshal the request body
	input := v1.UpdateOcpSharedConfigurationRequest{}
	if err := render.Bind(r, &input); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	if input.DefaultSandboxQuota != nil {
		ocpSharedClusterConfiguration.DefaultSandboxQuota = *&input.DefaultSandboxQuota
	}

	if input.QuotaRequired != nil {
		ocpSharedClusterConfiguration.QuotaRequired = *input.QuotaRequired
	}

	if input.StrictDefaultSandboxQuota != nil {
		ocpSharedClusterConfiguration.StrictDefaultSandboxQuota = *input.StrictDefaultSandboxQuota
	}

	if input.Annotations != nil {
		ocpSharedClusterConfiguration.Annotations = *input.Annotations
	}

	if input.Token != nil {
		ocpSharedClusterConfiguration.Token = *input.Token
	}

	if input.AdditionalVars != nil {
		ocpSharedClusterConfiguration.AdditionalVars = input.AdditionalVars
	}

	if input.MaxMemoryUsagePercentage != nil {
		ocpSharedClusterConfiguration.MaxMemoryUsagePercentage = *input.MaxMemoryUsagePercentage
	}

	if input.MaxCpuUsagePercentage != nil {
		ocpSharedClusterConfiguration.MaxCpuUsagePercentage = *input.MaxCpuUsagePercentage
	}

	if input.SkipQuota != nil {
		ocpSharedClusterConfiguration.SkipQuota = *input.SkipQuota
	}

	if input.LimitRange != nil {
		ocpSharedClusterConfiguration.LimitRange = input.LimitRange
	}

	if input.UsageNodeSelector != nil {
		ocpSharedClusterConfiguration.UsageNodeSelector = *input.UsageNodeSelector
	}

	if input.NetboxApiUrl != nil {
		ocpSharedClusterConfiguration.NetboxApiUrl = *input.NetboxApiUrl
	}	

	if input.NetboxToken != nil {
		ocpSharedClusterConfiguration.NetboxToken = *input.NetboxToken
	}

	if err := ocpSharedClusterConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to update OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP shared cluster configuration updated",
	})
}
