package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/go-chi/render"
)

func (h *BaseHandler) CreateIBMSharedSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	IBMSharedSandboxConfiguration := models.MakeIBMSharedSandboxConfiguration()

	if err := render.Bind(r, IBMSharedSandboxConfiguration); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	IBMSharedSandboxConfiguration.DbPool = h.IBMSharedSandboxProvider.DbPool
	IBMSharedSandboxConfiguration.VaultSecret = h.IBMSharedSandboxProvider.VaultSecret

	if err := IBMSharedSandboxConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to save IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM shared account configuration created",
	})
}

// Disable an IBM shared account configuration
func (h *BaseHandler) DisableIBMSharedSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM shared account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM shared account configuration from the database
	IBMSharedSandboxConfiguration, err := h.IBMSharedSandboxProvider.GetIBMSharedSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM shared account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Disable the IBM shared account configuration
	if err := IBMSharedSandboxConfiguration.Disable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to disable IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM shared account configuration is disabled",
	})
}

func (h *BaseHandler) EnableIBMSharedSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM shared account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM shared account configuration from the database
	IBMSharedSandboxConfiguration, err := h.IBMSharedSandboxProvider.GetIBMSharedSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM shared account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Enable the IBM shared account configuration
	if err := IBMSharedSandboxConfiguration.Enable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to enable IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM shared account configuration is enabled",
	})
}

// GetIBMSharedSandboxConfigurationsHandlers returns a list of IBM shared account configurations
func (h *BaseHandler) GetIBMSharedSandboxConfigurationsHandler(w http.ResponseWriter, r *http.Request) {
	IBMSharedSandboxConfigurations, err := h.IBMSharedSandboxProvider.GetIBMSharedSandboxConfigurations()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM shared account configurations",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &IBMSharedSandboxConfigurations)
}

// GetIBMSharedSandboxConfigurationHandler returns a single IBM shared account configuration
func (h *BaseHandler) GetIBMSharedSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM shared account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM shared account configuration from the database
	IBMSharedSandboxConfiguration, err := h.IBMSharedSandboxProvider.GetIBMSharedSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM shared account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &IBMSharedSandboxConfiguration)
}

// DeleteIBMSharedSandboxConfigurationHandler deletes an IBM shared account configuration
func (h *BaseHandler) DeleteIBMSharedSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM shared account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM shared account configuration from the database
	IBMSharedSandboxConfiguration, err := h.IBMSharedSandboxProvider.GetIBMSharedSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM shared account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	count, err := IBMSharedSandboxConfiguration.GetAccountCount()
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
			Message:        "IBM shared account configuration has accounts associated with it",
		})
		return
	}

	// Delete the IBM shared account configuration
	if err := IBMSharedSandboxConfiguration.Delete(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to delete IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM shared account configuration deleted",
	})
}

func (h *BaseHandler) UpdateIBMSharedSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM shared account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM shared account configuration from the database
	IBMSharedSandboxConfiguration, err := h.IBMSharedSandboxProvider.GetIBMSharedSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM shared account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// unmarshal the request body
	input := v1.UpdateIBMSharedSandboxConfigurationRequest{}
	if err := render.Bind(r, &input); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	if input.Annotations != nil {
		IBMSharedSandboxConfiguration.Annotations = *input.Annotations
	}

	if input.APIKey != nil {
		IBMSharedSandboxConfiguration.APIKey = *input.APIKey
	}

	if input.AdditionalVars != nil {
		IBMSharedSandboxConfiguration.AdditionalVars = input.AdditionalVars
	}

	if err := IBMSharedSandboxConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to update IBM shared account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM shared account configuration updated",
	})
}
