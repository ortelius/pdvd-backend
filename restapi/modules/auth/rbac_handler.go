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
func HandleRBACApply(db database.DBConnection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		user, err := getUserFromRequest(r)
		if err != nil {
			sendErrorResponse(w, http.StatusUnauthorized, "Authentication required")
			return
		}

		if !user.IsAdmin() {
			sendErrorResponse(w, http.StatusForbidden, "Admin access required")
			return
		}

		var req RBACApplyRequest
		contentType := r.Header.Get("Content-Type")

		switch {
		case strings.Contains(contentType, "application/json"):
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				sendErrorResponse(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
				return
			}
		case strings.Contains(contentType, "application/x-yaml") || strings.Contains(contentType, "text/yaml"):
			body, err := io.ReadAll(r.Body)
			if err != nil {
				sendErrorResponse(w, http.StatusBadRequest, "Failed to read request body")
				return
			}
			req.Config = string(body)
		default:
			sendErrorResponse(w, http.StatusBadRequest, "Content-Type must be application/json or application/x-yaml")
			return
		}

		if req.Config == "" {
			sendErrorResponse(w, http.StatusBadRequest, "RBAC config cannot be empty")
			return
		}

		var config RBACConfig
		if err := yaml.Unmarshal([]byte(req.Config), &config); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid YAML: "+err.Error())
			return
		}

		if err := ValidateRBACConfig(&config); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid RBAC config: "+err.Error())
			return
		}

		if req.DryRun {
			response := RBACApplyResponse{
				Success: true,
				Message: fmt.Sprintf("Dry run successful. Config is valid. Would create/update %d users and %d roles.",
					len(config.Users), len(config.Roles)),
			}
			sendJSONResponse(w, http.StatusOK, response)
			return
		}

		usersCreated, usersUpdated, rolesCreated, errs := ApplyRBACConfig(db, &config)

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
func HandleRBACValidate(_ database.DBConnection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		user, err := getUserFromRequest(r)
		if err != nil {
			sendErrorResponse(w, http.StatusUnauthorized, "Authentication required")
			return
		}

		if !user.IsAdmin() {
			sendErrorResponse(w, http.StatusForbidden, "Admin access required")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Failed to read request body")
			return
		}

		var config RBACConfig
		if err := yaml.Unmarshal(body, &config); err != nil {
			sendErrorResponse(w, http.StatusBadRequest, "Invalid YAML: "+err.Error())
			return
		}

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

func getUserFromRequest(r *http.Request) (*model.User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	claims, err := ValidateJWT(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	user := &model.User{
		Username: claims.Username,
		Role:     claims.Role,
		Orgs:     claims.Orgs,
		IsActive: true,
	}

	return user, nil
}

func sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Printf("ERROR: Failed to encode JSON response: %v\n", err)
	}
}

func sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	response := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	sendJSONResponse(w, statusCode, response)
}
