// Package auth provides RBAC handlers for Fiber.
package auth

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"gopkg.in/yaml.v2"
)

// ============================================================================
// RBAC HANDLERS (Fiber)
// ============================================================================

// ApplyRBACFromBody applies RBAC config from request body
func ApplyRBACFromBody(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Config string `json:"config"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		config, err := LoadPeriobolosConfig(req.Config)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("Invalid RBAC config: %v", err),
			})
		}

		result, err := ApplyRBAC(db, config, emailConfig)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to apply RBAC: %v", err),
			})
		}

		return c.JSON(fiber.Map{
			"message": "RBAC applied successfully",
			"result":  result,
		})
	}
}

// ApplyRBACFromUpload applies RBAC config from uploaded file
func ApplyRBACFromUpload(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		file, err := c.FormFile("file")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "No file uploaded",
			})
		}

		openedFile, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to open file",
			})
		}
		defer openedFile.Close()

		yamlContent, err := io.ReadAll(openedFile)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to read file",
			})
		}

		config, err := LoadPeriobolosConfig(string(yamlContent))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("Invalid RBAC config: %v", err),
			})
		}

		result, err := ApplyRBAC(db, config, emailConfig)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to apply RBAC: %v", err),
			})
		}

		return c.JSON(fiber.Map{
			"message": "RBAC applied successfully from upload",
			"result":  result,
		})
	}
}

// ApplyRBACFromFile applies RBAC config from filesystem
func ApplyRBACFromFile(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			FilePath string `json:"file_path"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if req.FilePath == "" {
			req.FilePath = "/etc/pdvd/rbac.yaml"
		}

		if _, err := os.Stat(req.FilePath); err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": fmt.Sprintf("File not found: %s", req.FilePath),
			})
		}

		yamlContent, err := os.ReadFile(req.FilePath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to read file",
			})
		}

		config, err := LoadPeriobolosConfig(string(yamlContent))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("Invalid RBAC config: %v", err),
			})
		}

		result, err := ApplyRBAC(db, config, emailConfig)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to apply RBAC: %v", err),
			})
		}

		return c.JSON(fiber.Map{
			"message": fmt.Sprintf("RBAC applied successfully from %s", req.FilePath),
			"result":  result,
		})
	}
}

// GetRBACConfig exports current RBAC configuration
func GetRBACConfig(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		config, err := ExportRBACConfig(db)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to export RBAC config",
			})
		}

		yamlData, err := yaml.Marshal(config)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to marshal config",
			})
		}

		c.Set("Content-Type", "application/x-yaml")
		return c.Send(yamlData)
	}
}

// ============================================================================
// RBAC LOGIC
// ============================================================================

// PeriobolosConfig represents the Peribolos-style RBAC configuration
type PeriobolosConfig struct {
	Users []PeriobolosUser `yaml:"users"`
}

// PeriobolosUser represents a user in Peribolos config
type PeriobolosUser struct {
	Username string   `yaml:"username"`
	Email    string   `yaml:"email"`
	Role     string   `yaml:"role"`
	Orgs     []string `yaml:"orgs,omitempty"`
}

// RBACResult represents the result of applying RBAC
type RBACResult struct {
	Created []string `json:"created"`
	Updated []string `json:"updated"`
	Removed []string `json:"removed"`
	Invited []string `json:"invited"`
}

// LoadPeriobolosConfig loads and validates RBAC config from YAML string
func LoadPeriobolosConfig(yamlContent string) (*PeriobolosConfig, error) {
	var config PeriobolosConfig
	if err := yaml.Unmarshal([]byte(yamlContent), &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate
	for i, user := range config.Users {
		if user.Username == "" {
			return nil, fmt.Errorf("user at index %d has empty username", i)
		}
		if user.Email == "" {
			return nil, fmt.Errorf("user %s has empty email", user.Username)
		}
		if user.Role == "" {
			return nil, fmt.Errorf("user %s has empty role", user.Username)
		}
		if user.Role != "admin" && user.Role != "editor" && user.Role != "viewer" {
			return nil, fmt.Errorf("user %s has invalid role: %s", user.Username, user.Role)
		}
	}

	return &config, nil
}

// ApplyRBAC applies the RBAC configuration to the database
func ApplyRBAC(db database.DBConnection, config *PeriobolosConfig, emailConfig *EmailConfig) (*RBACResult, error) {
	ctx := context.Background()
	result := &RBACResult{
		Created: []string{},
		Updated: []string{},
		Removed: []string{},
		Invited: []string{},
	}

	// Get existing users
	existingUsers, err := listUsers(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("failed to list existing users: %w", err)
	}

	existingUserMap := make(map[string]*model.User)
	for _, u := range existingUsers {
		existingUserMap[u.Username] = u
	}

	// Process each user in config
	for _, configUser := range config.Users {
		existingUser, exists := existingUserMap[configUser.Username]

		if !exists {
			// Create new user with pending status and send invitation
			user := model.NewUser(configUser.Username, configUser.Role)
			user.Email = configUser.Email
			user.Orgs = configUser.Orgs
			user.IsActive = false
			user.Status = "pending"

			// Generate random password (will be replaced when invitation accepted)
			randomPass, _ := GenerateSecureToken(32)
			passwordHash, _ := HashPassword(randomPass)
			user.PasswordHash = passwordHash

			if err := createUser(ctx, db, user); err != nil {
				return nil, fmt.Errorf("failed to create user %s: %w", configUser.Username, err)
			}

			// Send invitation
			_, err := CreateInvitation(ctx, db, emailConfig, configUser.Username, configUser.Email, configUser.Role)
			if err != nil {
				fmt.Printf("⚠️  Failed to send invitation to %s: %v\n", configUser.Username, err)
			} else {
				result.Invited = append(result.Invited, configUser.Username)
			}

			result.Created = append(result.Created, configUser.Username)
		} else {
			// Update existing user
			needsUpdate := false

			if existingUser.Email != configUser.Email {
				existingUser.Email = configUser.Email
				needsUpdate = true
			}
			if existingUser.Role != configUser.Role {
				existingUser.Role = configUser.Role
				needsUpdate = true
			}
			if !stringSlicesEqual(existingUser.Orgs, configUser.Orgs) {
				existingUser.Orgs = configUser.Orgs
				needsUpdate = true
			}

			if needsUpdate {
				existingUser.UpdatedAt = time.Now()
				if err := updateUser(ctx, db, existingUser); err != nil {
					return nil, fmt.Errorf("failed to update user %s: %w", configUser.Username, err)
				}
				result.Updated = append(result.Updated, configUser.Username)
			}
		}

		// Remove from map to track which users to remove
		delete(existingUserMap, configUser.Username)
	}

	// Remaining users in map should be removed (not in config)
	for username := range existingUserMap {
		// Don't auto-remove users - just report
		// In production, you might want to deactivate instead
		fmt.Printf("⚠️  User %s not in config (not removing automatically)\n", username)
	}

	return result, nil
}

// stringSlicesEqual checks if two string slices are equal
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
