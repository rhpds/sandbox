package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/go-chi/render"
)

func (h *BaseHandler) CreateIBMResourceGroupSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	IBMResourceGroupSandboxConfiguration := models.MakeIBMResourceGroupSandboxConfiguration()

	if err := render.Bind(r, IBMResourceGroupSandboxConfiguration); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	IBMResourceGroupSandboxConfiguration.DbPool = h.IBMResourceGroupSandboxProvider.DbPool
	IBMResourceGroupSandboxConfiguration.VaultSecret = h.IBMResourceGroupSandboxProvider.VaultSecret

	if err := IBMResourceGroupSandboxConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to save IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM resource group account configuration created",
	})
}

// Disable an IBM resource group account configuration
func (h *BaseHandler) DisableIBMResourceGroupSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM resource group account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM resource group account configuration from the database
	IBMResourceGroupSandboxConfiguration, err := h.IBMResourceGroupSandboxProvider.GetIBMResourceGroupSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM resource group account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Disable the IBM resource group account configuration
	if err := IBMResourceGroupSandboxConfiguration.Disable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to disable IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM resource group account configuration is disabled",
	})
}

func (h *BaseHandler) EnableIBMResourceGroupSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM resource group account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM resource group account configuration from the database
	IBMResourceGroupSandboxConfiguration, err := h.IBMResourceGroupSandboxProvider.GetIBMResourceGroupSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM resource group account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Enable the IBM resource group account configuration
	if err := IBMResourceGroupSandboxConfiguration.Enable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to enable IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM resource group account configuration is enabled",
	})
}

// GetIBMResourceGroupSandboxConfigurationsHandlers returns a list of IBM resource group account configurations
func (h *BaseHandler) GetIBMResourceGroupSandboxConfigurationsHandler(w http.ResponseWriter, r *http.Request) {
	IBMResourceGroupSandboxConfigurations, err := h.IBMResourceGroupSandboxProvider.GetIBMResourceGroupSandboxConfigurations()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM resource group account configurations",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &IBMResourceGroupSandboxConfigurations)
}

// GetIBMResourceGroupSandboxConfigurationHandler returns a single IBM resource group account configuration
func (h *BaseHandler) GetIBMResourceGroupSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM resource group account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM resource group account configuration from the database
	IBMResourceGroupSandboxConfiguration, err := h.IBMResourceGroupSandboxProvider.GetIBMResourceGroupSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM resource group account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &IBMResourceGroupSandboxConfiguration)
}

// DeleteIBMResourceGroupSandboxConfigurationHandler deletes an IBM resource group account configuration
func (h *BaseHandler) DeleteIBMResourceGroupSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM resource group account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM resource group account configuration from the database
	IBMResourceGroupSandboxConfiguration, err := h.IBMResourceGroupSandboxProvider.GetIBMResourceGroupSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM resource group account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	count, err := IBMResourceGroupSandboxConfiguration.GetAccountCount()
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
			Message:        "IBM resource group account configuration has accounts associated with it",
		})
		return
	}

	// Delete the IBM resource group account configuration
	if err := IBMResourceGroupSandboxConfiguration.Delete(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to delete IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM resource group account configuration deleted",
	})
}

func (h *BaseHandler) UpdateIBMResourceGroupSandboxConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the IBM resource group account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the IBM resource group account configuration from the database
	IBMResourceGroupSandboxConfiguration, err := h.IBMResourceGroupSandboxProvider.GetIBMResourceGroupSandboxConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "IBM resource group account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// unmarshal the request body
	input := v1.UpdateIBMResourceGroupSandboxConfigurationRequest{}
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
		IBMResourceGroupSandboxConfiguration.Annotations = *input.Annotations
	}

	if input.APIKey != nil {
		IBMResourceGroupSandboxConfiguration.APIKey = *input.APIKey
	}

	if input.AdditionalVars != nil {
		IBMResourceGroupSandboxConfiguration.AdditionalVars = input.AdditionalVars
	}

	if err := IBMResourceGroupSandboxConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to update IBM resource group account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "IBM resource group account configuration updated",
	})
}
