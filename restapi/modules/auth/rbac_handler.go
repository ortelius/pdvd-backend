// Package auth provides authentication and authorization utilities.
//
//revive:disable-next-line:var-naming
package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"gopkg.in/yaml.v2"
)

// ============================================================================
// RBAC CONFIGURATION API HANDLER
// ============================================================================

// RBACApplyRequest represents the request body for applying RBAC config
type RBACApplyRequest struct {
	Config string `json:"config"` // YAML config as string
	DryRun bool   `json:"dry_run,omitempty"`
}

// RBACApplyResponse represents the response from applying RBAC config
type RBACApplyResponse struct {
	Success      bool     `json:"success"`
	Message      string   `json:"message"`
	UsersCreated int      `json:"users_created,omitempty"`
	UsersUpdated int      `json:"users_updated,omitempty"`
	RolesCreated int      `json:"roles_created,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

// HandleRBACApply handles POST /api/v1/rbac/apply
// Accepts RBAC configuration in YAML format and applies it to the database
// ADMIN ONLY - This endpoint is restricted to users with admin role
func HandleRBACApply(db database.DBConnection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodPost {
			sendErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		// Get authenticated user from context
		user, err := getUserFromRequest(r)
		if err != nil {
			sendErrorResponse(w, http.StatusUnauthorized, "Authentication required")
			return
		}

		// Verify user is admin
		if !user.IsAdmin() {
			sendErrorResponse(w, http.StatusForbidden, "Admin access required")
			return
		}

		// Parse request body
		var req RBACApplyRequest

		// Check Content-Type
		contentType := r.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			// JSON request body
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				sendErrorResponse(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
				return
			}
		} else if strings.Contains(contentType, "application/x-yaml") || strings.Contains(contentType, "text/yaml") {
			// YAML request body directly
			body, err := io.ReadAll(r.Body)
			if err != nil {
				sendErrorResponse(w, http.StatusBadRequest, "Failed to read request body")
				return
			}
			req.Config = string(body)
		} else {
			sendErrorResponse(w, http.StatusBadRequest, "Content-Type must be application/json or application/x-yaml")
			return
		}

		if req.Config == "" {
			sendErrorResponse(w, http.StatusBadRequest, "RBAC config cannot be empty")
			return
		}

		// Parse YAML config
		var config RBACConfig
		if err := yaml.Unmarshal([]byte(req.Config), &config); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid YAML: "+err.Error())
			return
		}

		// Validate config
		if err := ValidateRBACConfig(&config); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid RBAC config: "+err.Error())
			return
		}

		// Dry run mode - validate only, don't apply
		if req.DryRun {
			response := RBACApplyResponse{
				Success: true,
				Message: fmt.Sprintf("Dry run successful. Config is valid. Would create/update %d users and %d roles.",
					len(config.Users), len(config.Roles)),
			}
			sendJSONResponse(w, http.StatusOK, response)
			return
		}

		// Apply config to database
		usersCreated, usersUpdated, rolesCreated, errs := ApplyRBACConfig(db, &config)

		// Build response
		response := RBACApplyResponse{
			Success:      len(errs) == 0,
			UsersCreated: usersCreated,
			UsersUpdated: usersUpdated,
			RolesCreated: rolesCreated,
		}

		if len(errs) > 0 {
			response.Message = "RBAC config applied with errors"
			response.Errors = make([]string, len(errs))
			for i, err := range errs {
				response.Errors[i] = err.Error()
			}
			sendJSONResponse(w, http.StatusPartialContent, response)
			return
		}

		response.Message = fmt.Sprintf("RBAC config applied successfully. Created %d users, updated %d users, created %d roles.",
			usersCreated, usersUpdated, rolesCreated)
		sendJSONResponse(w, http.StatusOK, response)
	}
}

// HandleRBACValidate handles POST /api/v1/rbac/validate
// Validates RBAC configuration without applying it
// ADMIN ONLY
func HandleRBACValidate(db database.DBConnection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		// Get authenticated user
		user, err := getUserFromRequest(r)
		if err != nil {
			sendErrorResponse(w, http.StatusUnauthorized, "Authentication required")
			return
		}

		// Verify admin
		if !user.IsAdmin() {
			sendErrorResponse(w, http.StatusForbidden, "Admin access required")
			return
		}

		// Read request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Failed to read request body")
			return
		}

		// Parse YAML
		var config RBACConfig
		if err := yaml.Unmarshal(body, &config); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid YAML: "+err.Error())
			return
		}

		// Validate
		if err := ValidateRBACConfig(&config); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid RBAC config: "+err.Error())
			return
		}

		response := RBACApplyResponse{
			Success: true,
			Message: fmt.Sprintf("Config is valid. Contains %d users and %d roles.",
				len(config.Users), len(config.Roles)),
		}
		sendJSONResponse(w, http.StatusOK, response)
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// getUserFromRequest extracts the authenticated user from the request context
// This assumes your auth middleware has set the user in the request context
func getUserFromRequest(r *http.Request) (*model.User, error) {
	// IMPORTANT: Update this to match your actual context key
	// Example options:
	// 1. user := r.Context().Value("user").(*User)
	// 2. user := r.Context().Value(middleware.UserContextKey).(*User)
	// 3. Extract from JWT in Authorization header

	// For now, extracting from Authorization header as fallback
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}

	// Expected format: "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	// Validate JWT and extract claims
	claims, err := ValidateJWT(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Build user from claims
	// NOTE: In production, you might want to fetch the full user from DB
	user := &model.User{
		Username: claims.Username,
		Role:     claims.Role,
		Orgs:     claims.Orgs,
		IsActive: true,
	}

	return user, nil
}

// sendJSONResponse sends a JSON response with the given status code
func sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log error but don't try to send another response
		fmt.Printf("ERROR: Failed to encode JSON response: %v\n", err)
	}
}

// sendErrorResponse sends a JSON error response
func sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	response := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	sendJSONResponse(w, statusCode, response)
}
