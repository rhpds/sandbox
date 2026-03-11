package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/jackc/pgx/v4"
	"github.com/rhpds/sandbox/internal/api/v1"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"
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

	// Record who created this cluster
	_, claims, _ := jwtauth.FromContext(r.Context())
	if name, ok := claims["name"].(string); ok {
		ocpSharedClusterConfiguration.CreatedBy = name
	}

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

// ListOcpSharedClusterConfigurationsHandler returns all OCP shared cluster configurations.
// Admin gets full details. Manager gets full details for own clusters, shared view for others.
func (h *BaseHandler) ListOcpSharedClusterConfigurationsHandler(w http.ResponseWriter, r *http.Request) {
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

	// Populate current placement counts
	for i := range ocpSharedClusterConfigurations {
		count, err := ocpSharedClusterConfigurations[i].GetAccountCount()
		if err != nil {
			log.Logger.Error("Error getting account count", "cluster", ocpSharedClusterConfigurations[i].Name, "error", err)
			continue
		}
		ocpSharedClusterConfigurations[i].Data.CurrentPlacementCount = &count
	}

	_, claims, _ := jwtauth.FromContext(r.Context())
	role, _ := claims["role"].(string)
	if role == "shared-cluster-manager" {
		callerName, _ := claims["name"].(string)
		var result models.OcpSharedClusterConfigurations
		for i := range ocpSharedClusterConfigurations {
			if ocpSharedClusterConfigurations[i].CreatedBy == callerName {
				result = append(result, ocpSharedClusterConfigurations[i])
			} else {
				result = append(result, ocpSharedClusterConfigurations[i].SharedView())
			}
		}
		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &result)
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &ocpSharedClusterConfigurations)
}

// GetOwnOcpSharedClusterConfigurationHandler returns a single OCP shared cluster configuration.
// Admin gets full details. Manager gets full details for own clusters, shared view for others.
func (h *BaseHandler) GetOwnOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

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

	_, claims, _ := jwtauth.FromContext(r.Context())
	role, _ := claims["role"].(string)
	if role == "shared-cluster-manager" {
		callerName, _ := claims["name"].(string)
		if ocpSharedClusterConfiguration.CreatedBy != callerName {
			// Non-owner: return shared view (no credentials or internal details)
			shared := ocpSharedClusterConfiguration.SharedView()
			w.WriteHeader(http.StatusOK)
			render.Render(w, r, &shared)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &ocpSharedClusterConfiguration)
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

	// Handle MaxPlacements: if set to -1, clear the limit (set to nil)
	// Any value >= 0 sets the limit
	if input.MaxPlacements != nil {
		if *input.MaxPlacements < 0 {
			ocpSharedClusterConfiguration.MaxPlacements = nil
		} else {
			ocpSharedClusterConfiguration.MaxPlacements = input.MaxPlacements
		}
	}

	if input.DeployerAdminSATokenTTL != nil {
		ocpSharedClusterConfiguration.DeployerAdminSATokenTTL = *input.DeployerAdminSATokenTTL
	}

	if input.DeployerAdminSATokenRefreshInterval != nil {
		ocpSharedClusterConfiguration.DeployerAdminSATokenRefreshInterval = *input.DeployerAdminSATokenRefreshInterval
	}

	if input.DeployerAdminSATokenTargetVar != nil {
		ocpSharedClusterConfiguration.DeployerAdminSATokenTargetVar = *input.DeployerAdminSATokenTargetVar
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

	// If deployer-admin SA token config changed, signal the background
	// rotation goroutine to pick it up immediately.
	if input.DeployerAdminSATokenTTL != nil || input.DeployerAdminSATokenRefreshInterval != nil || input.DeployerAdminSATokenTargetVar != nil {
		h.OcpSandboxProvider.TriggerRotation()
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, &v1.SimpleMessage{
		Message: "OCP shared cluster configuration updated",
	})
}

// UpsertOcpSharedClusterConfigurationHandler creates or updates an OcpSharedClusterConfiguration.
// If the cluster does not exist, it creates it (HTTP 201).
// If the cluster already exists, it replaces all fields (HTTP 200).
func (h *BaseHandler) UpsertOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	newConfig := models.MakeOcpSharedClusterConfiguration()
	if err := render.Bind(r, newConfig); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "Invalid request payload",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	if newConfig.Name != name {
		w.WriteHeader(http.StatusBadRequest)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusBadRequest,
			Message:        "name in URL path must match name in request body",
		})
		return
	}

	// Validate annotations unless ?force=true is set
	if r.URL.Query().Get("force") != "true" {
		if err := models.ValidateClusterAnnotations(newConfig.Annotations); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusBadRequest,
				Message:        err.Error() + " (use ?force=true to override)",
			})
			return
		}
	} else {
		log.Logger.Warn("Annotation validation bypassed with ?force=true",
			"cluster", newConfig.Name,
			"annotations", newConfig.Annotations)
	}

	newConfig.DbPool = h.OcpSandboxProvider.DbPool
	newConfig.VaultSecret = h.OcpSandboxProvider.VaultSecret

	existing, err := h.OcpSandboxProvider.GetOcpSharedClusterConfigurationByName(name)
	if err != nil && err != pgx.ErrNoRows {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to check existing OCP shared cluster configuration",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	if err == pgx.ErrNoRows {
		// Create path

		// Record who created this cluster
		_, claims, _ := jwtauth.FromContext(r.Context())
		if claimName, ok := claims["name"].(string); ok {
			newConfig.CreatedBy = claimName
		}

		// Handle MaxPlacements: -1 means "no limit" (nil)
		if newConfig.MaxPlacements != nil && *newConfig.MaxPlacements < 0 {
			newConfig.MaxPlacements = nil
		}

		if err := newConfig.Save(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Failed to save OCP shared cluster configuration",
				ErrorMultiline: []string{err.Error()},
			})
			return
		}

		// Trigger token rotation if deployer-admin SA token is configured
		if newConfig.DeployerAdminSATokenTTL != "" {
			h.OcpSandboxProvider.TriggerRotation()
		}

		w.WriteHeader(http.StatusCreated)
		render.Render(w, r, &v1.SimpleMessage{
			Message: "OCP shared cluster configuration created",
		})
	} else {
		// Authorization check: caller must be allowed to modify this cluster.
		_, claims, _ := jwtauth.FromContext(r.Context())
		role, _ := claims["role"].(string)
		callerName, _ := claims["name"].(string)
		if !existing.CanModify(role, callerName) {
			w.WriteHeader(http.StatusForbidden)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusForbidden,
				Message:        "You are not allowed to update this cluster",
			})
			return
		}

		// Update: preserve the DB ID so Save() calls Update()
		newConfig.ID = existing.ID

		// Preserve deployer admin SA token if not provided in the request
		// (the token is managed by the background rotation goroutine)
		if newConfig.DeployerAdminSAToken == "" {
			newConfig.DeployerAdminSAToken = existing.DeployerAdminSAToken
		}

		// Preserve internal data (rotation count, timestamps, etc.)
		// Save AllowedUpdateRoles from the request before overwriting with existing Data.
		requestedAllowedUpdateRoles := newConfig.Data.AllowedUpdateRoles
		newConfig.Data = existing.Data
		if requestedAllowedUpdateRoles != nil {
			newConfig.Data.AllowedUpdateRoles = requestedAllowedUpdateRoles
		}

		// Handle MaxPlacements: -1 means "clear the limit" (same as the update endpoint)
		if newConfig.MaxPlacements != nil && *newConfig.MaxPlacements < 0 {
			newConfig.MaxPlacements = nil
		}

		if err := newConfig.Save(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Failed to update OCP shared cluster configuration",
				ErrorMultiline: []string{err.Error()},
			})
			return
		}

		// If deployer-admin SA token config changed, signal the background
		// rotation goroutine to pick it up immediately.
		if newConfig.DeployerAdminSATokenTTL != existing.DeployerAdminSATokenTTL ||
			newConfig.DeployerAdminSATokenRefreshInterval != existing.DeployerAdminSATokenRefreshInterval ||
			newConfig.DeployerAdminSATokenTargetVar != existing.DeployerAdminSATokenTargetVar {
			h.OcpSandboxProvider.TriggerRotation()
		}

		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &v1.SimpleMessage{
			Message: "OCP shared cluster configuration updated",
		})
	}
}

// OffboardOcpSharedClusterConfigurationHandler handles the full offboarding of a shared cluster.
//
// Flow:
//  1. Disable the cluster to prevent new scheduling.
//  2. Find all placements targeting this cluster.
//  3. If any placements span multiple clusters, return 409 (manual intervention required).
//  4. If no placements exist, delete the cluster config synchronously and return 200.
//  5. If placements exist, check cluster reachability.
//  6. If cluster is NOT reachable and no ?force=true, return 409.
//  7. If cluster is NOT reachable and ?force=true, force-delete everything from DB synchronously (200).
//  8. If cluster IS reachable, create an async offboard job (202) for namespace cleanup.
//
// The offboard job status can be polled via GET /ocp-shared-cluster-configurations/{name}/offboard.
func (h *BaseHandler) OffboardOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	force := r.URL.Query().Get("force") == "true"

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

	// Authorization check: caller must be allowed to modify this cluster.
	// Owner is always allowed; otherwise the caller's role must appear in
	// Data.AllowedUpdateRoles (default: ["admin"]).
	_, claims, _ := jwtauth.FromContext(r.Context())
	role, _ := claims["role"].(string)
	callerName, _ := claims["name"].(string)
	if !cluster.CanModify(role, callerName) {
		w.WriteHeader(http.StatusForbidden)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusForbidden,
			Message:        "You are not allowed to offboard this cluster",
		})
		return
	}

	report := v1.OffboardReport{
		ClusterName:                      name,
		PlacementsDeleted:                []v1.OffboardPlacementInfo{},
		PlacementsRequiringManualCleanup: []v1.OffboardPlacementInfo{},
	}

	// Step 1: Disable the cluster to prevent new scheduling
	if cluster.Valid {
		if err := cluster.Disable(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Failed to disable OCP shared cluster configuration",
				ErrorMultiline: []string{err.Error()},
			})
			return
		}
	}
	report.ClusterDisabled = true

	// Step 2: Find all placements targeting this cluster
	placementInfos, err := h.OcpSandboxProvider.GetPlacementsByClusterName(name)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get placements for cluster",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Step 3: If any placements span multiple clusters, reject with 409
	var singleClusterPlacements []models.ClusterPlacementInfo
	for _, pi := range placementInfos {
		if !pi.OnlyThisCluster {
			report.PlacementsRequiringManualCleanup = append(report.PlacementsRequiringManualCleanup, v1.OffboardPlacementInfo{
				PlacementID:  pi.PlacementID,
				ServiceUuid:  pi.ServiceUuid,
				Status:       pi.Status,
				ClusterNames: pi.ClusterNames,
			})
		} else {
			singleClusterPlacements = append(singleClusterPlacements, pi)
		}
	}

	if len(report.PlacementsRequiringManualCleanup) > 0 {
		w.WriteHeader(http.StatusConflict)
		report.Message = fmt.Sprintf(
			"Cannot offboard: %d placement(s) span multiple clusters and must be deleted manually before offboarding. "+
				"Delete these placements first, then retry the offboard.",
			len(report.PlacementsRequiringManualCleanup),
		)
		render.Render(w, r, &report)
		return
	}

	// Step 4: No placements — delete cluster config synchronously
	if len(singleClusterPlacements) == 0 {
		if err := cluster.Delete(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Failed to delete OCP shared cluster configuration",
				ErrorMultiline: []string{err.Error()},
			})
			return
		}
		report.ClusterDeleted = true
		report.Message = "Cluster offboarded successfully. No placements found. Cluster configuration removed."
		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &report)
		return
	}

	// Step 5: There are single-cluster placements. Check cluster reachability.
	clusterReachable := cluster.TestConnection() == nil

	// Step 6: Cluster not reachable and no force — tell user to use ?force=true
	if !clusterReachable && !force {
		w.WriteHeader(http.StatusConflict)
		report.Message = fmt.Sprintf(
			"Cluster is not reachable and has %d placement(s). Cannot clean up namespaces on the cluster. "+
				"Use ?force=true to delete placements and resources from the database without cleaning up the actual cluster.",
			len(singleClusterPlacements),
		)
		render.Render(w, r, &report)
		return
	}

	// Step 7: Force-delete (cluster not reachable + force=true) — synchronous DB-only cleanup
	if !clusterReachable && force {
		for _, pi := range singleClusterPlacements {
			log.Logger.Warn("Force-deleting placement without cluster cleanup",
				"cluster", name,
				"service_uuid", pi.ServiceUuid,
			)
			if err := models.ForceDeleteResourcesAndPlacement(h.dbpool, pi.ServiceUuid, name); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				render.Render(w, r, &v1.Error{
					HTTPStatusCode: http.StatusInternalServerError,
					Message:        fmt.Sprintf("Failed to force-delete placement %s", pi.ServiceUuid),
					ErrorMultiline: []string{err.Error()},
				})
				return
			}
			report.PlacementsDeleted = append(report.PlacementsDeleted, v1.OffboardPlacementInfo{
				PlacementID: pi.PlacementID,
				ServiceUuid: pi.ServiceUuid,
				Status:      "force deleted",
			})
		}

		if err := cluster.Delete(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusInternalServerError,
				Message:        "Failed to delete OCP shared cluster configuration",
				ErrorMultiline: []string{err.Error()},
			})
			return
		}
		report.ClusterDeleted = true
		report.Message = fmt.Sprintf(
			"Cluster offboarded with force. %d placement(s) removed from database without cluster cleanup. Cluster configuration removed.",
			len(report.PlacementsDeleted),
		)
		w.WriteHeader(http.StatusOK)
		render.Render(w, r, &report)
		return
	}

	// Step 8: Cluster is reachable — create async offboard job for namespace cleanup
	job, err := h.OcpSandboxProvider.CreateOffboardJob(
		r.Context(),
		name,
		singleClusterPlacements,
		h.awsAccountProvider,
		h.DNSSandboxProvider,
		h.IBMResourceGroupSandboxProvider,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to create offboard job",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusAccepted)
	render.Render(w, r, &v1.LifecycleResponse{
		RequestID: job.RequestID,
		Status:    job.Status,
		Message: fmt.Sprintf(
			"Offboard started for cluster %s. %d placement(s) to process. Poll GET /api/v1/ocp-shared-cluster-configurations/%s/offboard for status.",
			name, len(singleClusterPlacements), name,
		),
	})
}

// GetOffboardOcpSharedClusterConfigurationHandler returns the status of the latest offboard job for a cluster.
func (h *BaseHandler) GetOffboardOcpSharedClusterConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	job, err := h.OcpSandboxProvider.GetOffboardJob(r.Context(), name)
	if err != nil {
		if err == pgx.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusNotFound,
				Message:        "No offboard job found for this cluster",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get offboard job",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, job)
}

// PostOcpSharedClustersStatusHandler is a placeholder for a handler that would
// handle requesting the status of all OCP shared clusters.
func (h *BaseHandler) PostOcpSharedClustersStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Self-heal any stale jobs before checking if one is in progress
	// This ensures we don't get stuck with zombie jobs
	if err := h.OcpSandboxProvider.SelfHealStaleFleetStatusJobs(r.Context()); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to check for stale fleet status jobs",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	// Check if a status request is already in progress
	if h.OcpSandboxProvider.IsOcpFleetStatusInProgress(r.Context()) {
		w.WriteHeader(http.StatusConflict)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusConflict,
			Message:        "A status check is already in progress. Please wait for it to complete before starting a new one.",
		})
		return
	}

	// Check for debug parameters and add them to context
	ctx := r.Context()
	if debugForceFail := r.URL.Query().Get("debug_force_fail"); debugForceFail != "" {
		ctx = context.WithValue(ctx, models.DebugForceFailKey, debugForceFail)
	}
	if debugForceTimeout := r.URL.Query().Get("debug_force_timeout"); debugForceTimeout != "" {
		ctx = context.WithValue(ctx, models.DebugForceTimeoutKey, debugForceTimeout)
	}

	// Parse and validate custom timeout
	timeout := models.FleetStatusTimeout // Default timeout
	if debugCustomTimeout := r.URL.Query().Get("debug_custom_timeout"); debugCustomTimeout != "" {
		if customDuration, err := time.ParseDuration(debugCustomTimeout); err == nil {
			timeout = customDuration
		} else {
			w.WriteHeader(http.StatusBadRequest)
			render.Render(w, r, &v1.Error{
				HTTPStatusCode: http.StatusBadRequest,
				Message:        "Invalid debug_custom_timeout format",
				ErrorMultiline: []string{fmt.Sprintf("Failed to parse duration '%s': %v", debugCustomTimeout, err)},
			})
			return
		}
	}
	// Add the parsed timeout to context
	ctx = context.WithValue(ctx, models.FleetStatusTimeoutKey, timeout)

	// Create a new fleet status job
	job, err := h.OcpSandboxProvider.CreateOcpFleetStatusJob(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to create OCP shared cluster status job",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusAccepted)
	render.Render(w, r, &v1.LifecycleResponse{
		RequestID: job.RequestID,
		Status:    job.Status,
		Message:   "Status Request successfully created",
	})
}

// GetOcpSharedClusterStatusHandler returns the status of all OCP shared clusters
func (h *BaseHandler) GetOcpSharedClustersStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the request ID from the URL
	// Get the status of all OCP shared clusters
	statusJob, err := h.OcpSandboxProvider.GetOcpFleetStatusJob(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.Render(w, r, &v1.Error{
			HTTPStatusCode: http.StatusInternalServerError,
			Message:        "Failed to get OCP shared cluster status",
			ErrorMultiline: []string{err.Error()},
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	render.Render(w, r, statusJob)
}
