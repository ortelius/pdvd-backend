// Package auth provides RBAC configuration management handlers.
package auth

import (
	"fmt"
	"io"

	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"gopkg.in/yaml.v2"
)

// ApplyRBACFromFile handles POST /api/v1/rbac/apply (file-based)
// It reconciles RBAC state using a configuration file path provided in the query string.
func ApplyRBACFromFile(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		configPath := c.Query("config", "/etc/pdvd/rbac.yaml")

		config, err := LoadPeriobolosConfig(configPath)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("Failed to load config: %v", err),
			})
		}

		// Reconcile database with config, passing emailConfig for invitations
		result, err := ApplyRBAC(db, config, emailConfig)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("RBAC apply failed: %v", err),
			})
		}

		return buildRBACResponse(c, result)
	}
}

// ApplyRBACFromBody handles POST /api/v1/rbac/apply/content (CI/CD push model)
// It accepts YAML configuration directly in the request body.
func ApplyRBACFromBody(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Read YAML content from request body
		body := c.Body()
		if len(body) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"error":   "Request body is empty. Send YAML content as request body.",
			})
		}

		// Parse YAML from body
		var config PeriobolosConfig
		if err := yaml.Unmarshal(body, &config); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("Failed to parse YAML: %v", err),
			})
		}

		// Validate parsed configuration
		if err := validateConfig(&config); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("Invalid config: %v", err),
			})
		}

		// Apply RBAC reconciliation
		result, err := ApplyRBAC(db, &config, emailConfig)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("RBAC apply failed: %v", err),
			})
		}

		return buildRBACResponse(c, result)
	}
}

// ApplyRBACFromUpload handles POST /api/v1/rbac/apply/upload (file upload)
// It allows manual reconciliation by uploading an rbac.yaml file.
func ApplyRBACFromUpload(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get uploaded file from form field 'file'
		file, err := c.FormFile("file")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"error":   "No file uploaded. Use 'file' as the form field name.",
			})
		}

		// Open the uploaded file
		src, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("Failed to open file: %v", err),
			})
		}
		defer src.Close()

		// Read entire file content
		content, err := io.ReadAll(src)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("Failed to read file: %v", err),
			})
		}

		// Parse YAML content
		var config PeriobolosConfig
		if err := yaml.Unmarshal(content, &config); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("Failed to parse YAML: %v", err),
			})
		}

		// Validate configuration structure
		if err := validateConfig(&config); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("Invalid config: %v", err),
			})
		}

		// Apply RBAC reconciliation
		result, err := ApplyRBAC(db, &config, emailConfig)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   fmt.Sprintf("RBAC apply failed: %v", err),
			})
		}

		return buildRBACResponse(c, result)
	}
}

// GetRBACConfig returns the current effective RBAC configuration (admin only)
// It transforms the database state into a Periobolos-style configuration object.
func GetRBACConfig(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.Context()

		users, err := getAllUsers(ctx, db)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch users",
			})
		}

		// Convert database users to PeriobolosUser format (excluding passwords)
		periobolosUsers := make([]PeriobolosUser, 0, len(users))
		for _, user := range users {
			periobolosUsers = append(periobolosUsers, PeriobolosUser{
				Username:     user.Username,
				Email:        user.Email,
				Role:         user.Role,
				IsActive:     user.IsActive,
				AuthProvider: user.AuthProvider,
				ExternalID:   user.ExternalID,
			})
		}

		config := PeriobolosConfig{
			Users: periobolosUsers,
		}

		return c.JSON(config)
	}
}

// buildRBACResponse creates a consistent JSON response for all RBAC operations
func buildRBACResponse(c *fiber.Ctx, result *RBACResult) error {
	response := fiber.Map{
		"success": len(result.Errors) == 0,
		"summary": fiber.Map{
			"created": len(result.Created),
			"updated": len(result.Updated),
			"removed": len(result.Removed),
			"invited": len(result.Invited),
			"errors":  len(result.Errors),
		},
		"details": fiber.Map{
			"created": result.Created,
			"updated": result.Updated,
			"removed": result.Removed,
			"invited": result.Invited,
			"errors":  result.Errors,
		},
	}

	// Include detailed invitation links if any were generated during reconciliation
	if len(result.Invitations) > 0 {
		response["invitations"] = result.Invitations
		response["message"] = "Invitation emails have been sent to new users. They must accept the invitation to activate their accounts."
	}

	statusCode := fiber.StatusOK
	if len(result.Errors) > 0 {
		statusCode = fiber.StatusMultiStatus
	}

	return c.Status(statusCode).JSON(response)
}
