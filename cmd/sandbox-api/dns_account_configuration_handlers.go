package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/go-chi/render"
)

func (h *BaseHandler) CreateDNSAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	dnsAccountConfiguration := models.MakeDNSAccountConfiguration()

	if err := render.Bind(r, dnsAccountConfiguration); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	dnsAccountConfiguration.DbPool = h.DNSSandboxProvider.DbPool
	dnsAccountConfiguration.VaultSecret = h.DNSSandboxProvider.VaultSecret

	if err := dnsAccountConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to save DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "DNS account configuration created",
	})
}

// Disable an DNS account configuration
func (h *BaseHandler) DisableDNSAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the DNS account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the DNS account configuration from the database
	dnsAccountConfiguration, err := h.DNSSandboxProvider.GetDNSAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "DNS account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Disable the DNS account configuration
	if err := dnsAccountConfiguration.Disable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to disable DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "DNS account configuration is disabled",
	})
}

func (h *BaseHandler) EnableDNSAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the DNS account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the DNS account configuration from the database
	dnsAccountConfiguration, err := h.DNSSandboxProvider.GetDNSAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "DNS account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Enable the DNS account configuration
	if err := dnsAccountConfiguration.Enable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to enable DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "DNS account configuration is enabled",
	})
}

// GetDNSAccountConfigurationsHandlers returns a list of DNS account configurations
func (h *BaseHandler) GetDNSAccountConfigurationsHandler(w http.ResponseWriter, r *http.Request) {
	dnsAccountConfigurations, err := h.DNSSandboxProvider.GetDNSAccountConfigurations()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get DNS account configurations",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &dnsAccountConfigurations)
}

// GetDNSAccountConfigurationHandler returns a single DNS account configuration
func (h *BaseHandler) GetDNSAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the DNS account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the DNS account configuration from the database
	dnsAccountConfiguration, err := h.DNSSandboxProvider.GetDNSAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "DNS account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &dnsAccountConfiguration)
}

// DeleteDNSAccountConfigurationHandler deletes an DNS account configuration
func (h *BaseHandler) DeleteDNSAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the DNS account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the DNS account configuration from the database
	dnsAccountConfiguration, err := h.DNSSandboxProvider.GetDNSAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "DNS account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	count, err := dnsAccountConfiguration.GetAccountCount()
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
			Message:        "DNS account configuration has accounts associated with it",
		})
		return
	}

	// Delete the DNS account configuration
	if err := dnsAccountConfiguration.Delete(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to delete DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "DNS account configuration deleted",
	})
}

func (h *BaseHandler) UpdateDNSAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// Get the name of the DNS account configuration from the URL
	name := chi.URLParam(r, "name")

	// Get the DNS account configuration from the database
	dnsAccountConfiguration, err := h.DNSSandboxProvider.GetDNSAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "DNS account configuration not found",
			})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// unmarshal the request body
	input := v1.UpdateDNSAccountConfigurationRequest{}
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
		dnsAccountConfiguration.Annotations = *input.Annotations
	}

	if input.AwsAccessKeyID != "" {
		dnsAccountConfiguration.AwsAccessKeyID = input.AwsAccessKeyID
	}

	if input.AwsSecretAccessKey != "" {
		dnsAccountConfiguration.AwsSecretAccessKey = input.AwsSecretAccessKey
	}

	if input.AdditionalVars != nil {
		dnsAccountConfiguration.AdditionalVars = input.AdditionalVars
	}

	if err := dnsAccountConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to update DNS account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "DNS account configuration updated",
	})
}
