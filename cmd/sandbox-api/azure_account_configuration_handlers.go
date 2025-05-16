package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/go-chi/render"
)

func (h *BaseHandler) CreateAzureAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	azureAccountConfiguration := models.MakeAzureAccountConfiguration()

	if err := render.Bind(r, azureAccountConfiguration); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	azureAccountConfiguration.DbPool = h.AzureSandboxProvider.DbPool
	azureAccountConfiguration.VaultSecret = h.AzureSandboxProvider.VaultSecret

	if err := azureAccountConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to save Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Azure account configuration created",
	})
}

// Disable an Azure account configuration
func (h *BaseHandler) DisableAzureAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the Azure account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the Azure account configuration from the database
	azureAccountConfiguration, err := h.AzureSandboxProvider.GetAzureAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Azure account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Disable the Azure account configuration
	if err := azureAccountConfiguration.Disable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to disable Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Azure account configuration is disabled",
	})
}

func (h *BaseHandler) EnableAzureAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the Azure account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the Azure account configuration from the database
	azureAccountConfiguration, err := h.AzureSandboxProvider.GetAzureAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Azure account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Enable the Azure account configuration
	if err := azureAccountConfiguration.Enable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to enable Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Azure account configuration is enabled",
	})
}

// GetAzureAccountConfigurationsHandlers returns a list of Azure account configurations
func (h *BaseHandler) GetAzureAccountConfigurationsHandler(w http.ResponseWriter, r *http.Request) {
	azureAccountConfigurations, err := h.AzureSandboxProvider.GetAzureAccountConfigurations()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get Azure account configurations",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &azureAccountConfigurations)
}

// GetAzureAccountConfigurationHandler returns a single Azure account configuration
func (h *BaseHandler) GetAzureAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the Azure account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the Azure account configuration from the database
	azureAccountConfiguration, err := h.AzureSandboxProvider.GetAzureAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Azure account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &azureAccountConfiguration)
}

// DeleteAzureAccountConfigurationHandler deletes an Azure account configuration
func (h *BaseHandler) DeleteAzureAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the Azure account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the Azure account configuration from the database
	azureAccountConfiguration, err := h.AzureSandboxProvider.GetAzureAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Azure account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	count, err := azureAccountConfiguration.GetAccountCount()
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
			Message:        "Azure account configuration has accounts associated with it",
		})
		return
	}

	// Delete the Azure account configuration
	if err := azureAccountConfiguration.Delete(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to delete Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Azure account configuration deleted",
	})
}

func (h *BaseHandler) UpdateAzureAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the Azure account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the Azure account configuration from the database
	azureAccountConfiguration, err := h.AzureSandboxProvider.GetAzureAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "Azure account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// unmarshal the request body
	input := v1.UpdateAzureAccountConfigurationRequest{}
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
		azureAccountConfiguration.Annotations = *input.Annotations
	}

	if input.ClientID != "" {
		azureAccountConfiguration.ClientID = input.ClientID
	}

	if input.TenantID != "" {
		azureAccountConfiguration.TenantID = input.TenantID
	}

	if input.Secret != "" {
		azureAccountConfiguration.Secret = input.Secret
	}

	if input.AdditionalVars != nil {
		azureAccountConfiguration.AdditionalVars = input.AdditionalVars
	}

	if err := azureAccountConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to update Azure account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "Azure account configuration updated",
	})
}
