package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/go-chi/render"
)

func (h *BaseHandler) CreateSSLAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	sslAccountConfiguration := models.MakeSSLAccountConfiguration()

	if err := render.Bind(r, sslAccountConfiguration); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	sslAccountConfiguration.DbPool = h.SSLSandboxProvider.DbPool
	sslAccountConfiguration.VaultSecret = h.SSLSandboxProvider.VaultSecret

	if err := sslAccountConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to save SSL account configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusCreated)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "SSL account configuration created",
	})
}

func (h *BaseHandler) DisableSSLAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	sslAccountConfiguration, err := h.SSLSandboxProvider.GetSSLAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusNotFound, Message: "SSL account configuration not found"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to get SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}
	if err := sslAccountConfiguration.Disable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to disable SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}
	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{Message: "SSL account configuration is disabled"})
}

func (h *BaseHandler) EnableSSLAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	sslAccountConfiguration, err := h.SSLSandboxProvider.GetSSLAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusNotFound, Message: "SSL account configuration not found"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to get SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}
	if err := sslAccountConfiguration.Enable(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to enable SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}
	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{Message: "SSL account configuration is enabled"})
}

func (h *BaseHandler) GetSSLAccountConfigurationsHandler(w http.ResponseWriter, r *http.Request) {
	sslAccountConfigurations, err := h.SSLSandboxProvider.GetSSLAccountConfigurations()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to get SSL account configurations", ErrorMultiline: []string{err.Error()}})
		return
	}
	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &sslAccountConfigurations)
}

func (h *BaseHandler) GetSSLAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	sslAccountConfiguration, err := h.SSLSandboxProvider.GetSSLAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusNotFound, Message: "SSL account configuration not found"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to get SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}
	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &sslAccountConfiguration)
}

func (h *BaseHandler) DeleteSSLAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	sslAccountConfiguration, err := h.SSLSandboxProvider.GetSSLAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusNotFound, Message: "SSL account configuration not found"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to get SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}
	count, err := sslAccountConfiguration.GetAccountCount()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to get account count", ErrorMultiline: []string{err.Error()}})
		return
	}
	if count > 0 {
		w.WriteHeader(http.StatusConflict)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusConflict, Message: "SSL account configuration has accounts associated with it"})
		return
	}
	if err := sslAccountConfiguration.Delete(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to delete SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}
	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{Message: "SSL account configuration deleted"})
}

func (h *BaseHandler) UpdateSSLAccountConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	sslAccountConfiguration, err := h.SSLSandboxProvider.GetSSLAccountConfigurationByName(name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusNotFound, Message: "SSL account configuration not found"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to get SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}

	input := v1.UpdateSSLAccountConfigurationRequest{}
	if err := render.Bind(r, &input); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusBadRequest, Message: "Invalid request payload", ErrorMultiline: []string{err.Error()}})
		return
	}

	if input.Annotations != nil {
		sslAccountConfiguration.Annotations = *input.Annotations
	}
	if input.Endpoint != "" {
		sslAccountConfiguration.Endpoint = input.Endpoint
	}
	if input.Token != "" {
		sslAccountConfiguration.Token = input.Token
	}
	if input.MainProviderURL != "" {
		sslAccountConfiguration.MainProviderURL = input.MainProviderURL
	}
	if input.FallbackProviderURL != "" {
		sslAccountConfiguration.FallbackProviderURL = input.FallbackProviderURL
	}
	if input.AdditionalVars != nil {
		sslAccountConfiguration.AdditionalVars = input.AdditionalVars
	}

	if err := sslAccountConfiguration.Save(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{HTTPStatusCode: http.StatusInternalServerError, Message: "Failed to update SSL account configuration", ErrorMultiline: []string{err.Error()}})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{Message: "SSL account configuration updated"})
}
