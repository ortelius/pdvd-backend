// Package auth provides RBAC handlers for Fiber.
package auth

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"gopkg.in/yaml.v2"
)

// ApplyRBACFromBody applies RBAC config from request body (YAML only)
func ApplyRBACFromBody(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		contentType := string(c.Request().Header.ContentType())

		if !strings.Contains(contentType, "application/x-yaml") &&
			!strings.Contains(contentType, "text/yaml") &&
			!strings.Contains(contentType, "application/yaml") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Content-Type must be application/x-yaml",
			})
		}

		yamlContent := string(c.Body())
		if yamlContent == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "RBAC config cannot be empty",
			})
		}

		config, err := LoadPeriobolosConfig(yamlContent)
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
			"success":     true,
			"message":     "RBAC applied successfully",
			"result":      result,
			"invitations": buildInvitationLinks(result.Invitations, emailConfig),
			"summary": fiber.Map{
				"orgs_created":  len(result.OrgsCreated),
				"orgs_updated":  len(result.OrgsUpdated),
				"users_created": len(result.Created),
				"users_updated": len(result.Updated),
				"users_removed": len(result.Removed),
				"invited":       len(result.Invited),
			},
		})
	}
}

// ValidateRBAC validates RBAC config without applying changes
func ValidateRBAC(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		yamlContent := string(c.Body())
		if yamlContent == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"valid": false,
				"error": "RBAC config cannot be empty",
			})
		}

		config, err := LoadPeriobolosConfig(yamlContent)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"valid": false,
				"error": err.Error(),
			})
		}

		ctx := context.Background()
		orgMapInYAML := make(map[string]bool)
		for _, org := range config.Orgs {
			orgMapInYAML[org.Name] = true
		}

		for _, user := range config.Users {
			for _, orgName := range user.Orgs {
				// Rule: User orgs must exist in current YAML or database
				if orgMapInYAML[orgName] {
					continue
				}
				if _, err := getOrgByName(ctx, db, orgName); err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"valid": false,
						"error": fmt.Sprintf("User %s references undefined org: %s", user.Username, orgName),
					})
				}
			}
		}

		return c.JSON(fiber.Map{
			"valid": true,
			"summary": fiber.Map{
				"orgs":  len(config.Orgs),
				"users": len(config.Users),
			},
		})
	}
}

// buildInvitationLinks generates invitation links for invited users
func buildInvitationLinks(invitations map[string]string, emailConfig *EmailConfig) map[string]string {
	links := make(map[string]string)
	for username, token := range invitations {
		links[username] = fmt.Sprintf("%s/invitation/%s", emailConfig.BaseURL, token)
	}
	return links
}

// ApplyRBACFromUpload applies RBAC config from uploaded file
func ApplyRBACFromUpload(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		file, err := c.FormFile("file")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "No file uploaded"})
		}

		openedFile, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to open file"})
		}
		defer openedFile.Close()

		yamlContent, err := io.ReadAll(openedFile)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
		}

		config, err := LoadPeriobolosConfig(string(yamlContent))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		result, err := ApplyRBAC(db, config, emailConfig)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"success": true, "result": result})
	}
}

// ApplyRBACFromFile applies RBAC config from filesystem
func ApplyRBACFromFile(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			FilePath string `json:"file_path"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
		}

		if req.FilePath == "" {
			req.FilePath = "/etc/pdvd/rbac.yaml"
		}

		yamlContent, err := os.ReadFile(req.FilePath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
		}

		config, err := LoadPeriobolosConfig(string(yamlContent))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		result, err := ApplyRBAC(db, config, emailConfig)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"success": true, "result": result})
	}
}

// GetRBACConfig exports current RBAC configuration from DB to YAML
func GetRBACConfig(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		config, err := ExportRBACConfig(db)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to export config"})
		}

		yamlData, err := yaml.Marshal(config)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to marshal config"})
		}

		c.Set("Content-Type", "application/x-yaml")
		return c.Send(yamlData)
	}
}

// PeriobolosConfig represents the RBAC configuration structure compatible with Peribolos-style YAML
type PeriobolosConfig struct {
	Orgs  []OrgDefinition  `yaml:"orgs,omitempty"`
	Users []PeriobolosUser `yaml:"users"`
	Roles []RoleDefinition `yaml:"roles,omitempty"`
}

// OrgDefinition represents an organization configuration
type OrgDefinition struct {
	Name        string            `yaml:"name"`
	DisplayName string            `yaml:"display_name,omitempty"`
	Description string            `yaml:"description,omitempty"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
}

// PeriobolosUser represents a user configuration in the RBAC system
type PeriobolosUser struct {
	Username     string   `yaml:"username"`
	Email        string   `yaml:"email"`
	Role         string   `yaml:"role"`
	Orgs         []string `yaml:"orgs,omitempty"`
	AuthProvider string   `yaml:"auth_provider,omitempty"`
}

// RoleDefinition represents a role configuration with associated permissions
type RoleDefinition struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Permissions []string `yaml:"permissions,omitempty"`
}

// RBACResult contains the outcome of applying RBAC configuration
type RBACResult struct {
	OrgsCreated []string          `json:"orgs_created"`
	OrgsUpdated []string          `json:"orgs_updated"`
	Created     []string          `json:"created"`
	Updated     []string          `json:"updated"`
	Removed     []string          `json:"removed"`
	Invited     []string          `json:"invited"`
	Invitations map[string]string `json:"invitations,omitempty"`
}

// LoadPeriobolosConfig parses RBAC configuration from YAML content
func LoadPeriobolosConfig(yamlContent string) (*PeriobolosConfig, error) {
	var config PeriobolosConfig
	if err := yaml.Unmarshal([]byte(yamlContent), &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	for i, user := range config.Users {
		if user.Username == "" {
			return nil, fmt.Errorf("user at index %d has empty username", i)
		}
		if user.Email == "" {
			return nil, fmt.Errorf("user %s has empty email", user.Username)
		}
		if user.Role != "admin" && user.Role != "editor" && user.Role != "viewer" {
			return nil, fmt.Errorf("user %s has invalid role: %s", user.Username, user.Role)
		}
	}
	return &config, nil
}

// ApplyRBAC implements Option B4: Read-Only Validation (Create/Update Orgs, No Delete)
func ApplyRBAC(db database.DBConnection, config *PeriobolosConfig, emailConfig *EmailConfig) (*RBACResult, error) {
	ctx := context.Background()
	result := &RBACResult{
		OrgsCreated: []string{},
		OrgsUpdated: []string{},
		Created:     []string{},
		Updated:     []string{},
		Removed:     []string{},
		Invited:     []string{},
		Invitations: make(map[string]string),
	}

	// 1. Process orgs from YAML (Rules: Create/Update only, never delete)
	orgMapInYAML := make(map[string]bool)
	for _, orgDef := range config.Orgs {
		orgMapInYAML[orgDef.Name] = true
		existingOrg, err := getOrgByName(ctx, db, orgDef.Name)

		if err != nil {
			// Not found - Create
			newOrg := &model.Org{
				Name:        orgDef.Name,
				DisplayName: orgDef.DisplayName,
				Description: orgDef.Description,
				Metadata:    orgDef.Metadata,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			if err := createOrg(ctx, db, newOrg); err != nil {
				return nil, fmt.Errorf("failed to create org %s: %w", orgDef.Name, err)
			}
			result.OrgsCreated = append(result.OrgsCreated, orgDef.Name)
		} else if existingOrg.DisplayName != orgDef.DisplayName || existingOrg.Description != orgDef.Description {
			// Found - Update display info if changed
			existingOrg.DisplayName = orgDef.DisplayName
			existingOrg.Description = orgDef.Description
			existingOrg.Metadata = orgDef.Metadata
			existingOrg.UpdatedAt = time.Now()
			if err := updateOrg(ctx, db, existingOrg); err != nil {
				return nil, fmt.Errorf("failed to update org %s: %w", orgDef.Name, err)
			}
			result.OrgsUpdated = append(result.OrgsUpdated, orgDef.Name)
		}
	}

	// 2. Process users and validate org references
	for _, configUser := range config.Users {
		for _, orgName := range configUser.Orgs {
			// Ensure org exists in either YAML definition or current Database
			if !orgMapInYAML[orgName] {
				if _, err := getOrgByName(ctx, db, orgName); err != nil {
					return nil, fmt.Errorf("user %s references undefined org: %s", configUser.Username, orgName)
				}
			}
		}
	}

	// 3. Source-of-Truth Sync for Users
	existingUsers, err := listUsers(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	existingUserMap := make(map[string]*model.User)
	for _, u := range existingUsers {
		existingUserMap[u.Username] = u
	}

	for _, configUser := range config.Users {
		existingUser, exists := existingUserMap[configUser.Username]

		if !exists {
			// Create new user in pending state
			user := model.NewUser(configUser.Username, configUser.Role)
			user.Email, user.Orgs, user.IsActive, user.Status = configUser.Email, configUser.Orgs, false, "pending"

			randomPass, _ := GenerateSecureToken(32)
			hash, _ := HashPassword(randomPass)
			user.PasswordHash = hash

			if err := createUser(ctx, db, user); err != nil {
				return nil, fmt.Errorf("failed to create user %s: %w", configUser.Username, err)
			}

			// Generate invitation for activation
			inv, err := CreateInvitation(ctx, db, emailConfig, configUser.Username, configUser.Email, configUser.Role)
			if err == nil {
				result.Invited = append(result.Invited, configUser.Username)
				result.Invitations[configUser.Username] = inv.Token
			}
			result.Created = append(result.Created, configUser.Username)
		} else {
			// Update existing user if metadata changed
			needsUpdate := false
			if existingUser.Email != configUser.Email || existingUser.Role != configUser.Role || !stringSlicesEqual(existingUser.Orgs, configUser.Orgs) {
				existingUser.Email, existingUser.Role, existingUser.Orgs = configUser.Email, configUser.Role, configUser.Orgs
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
		delete(existingUserMap, configUser.Username)
	}

	// Soft-delete (deactivate) users no longer present in YAML
	for username, user := range existingUserMap {
		user.IsActive, user.Status, user.UpdatedAt = false, "removed", time.Now()
		if err := updateUser(ctx, db, user); err == nil {
			result.Removed = append(result.Removed, username)
		}
	}

	return result, nil
}

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

func getOrgByName(ctx context.Context, db database.DBConnection, name string) (*model.Org, error) {
	query := `FOR org IN orgs FILTER org.name == @name RETURN org`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"name": name},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var org model.Org
	if !cursor.HasMore() {
		return nil, fmt.Errorf("org not found")
	}
	_, err = cursor.ReadDocument(ctx, &org)
	return &org, err
}

func createOrg(ctx context.Context, db database.DBConnection, org *model.Org) error {
	_, err := db.Collections["orgs"].CreateDocument(ctx, org)
	return err
}

func updateOrg(ctx context.Context, db database.DBConnection, org *model.Org) error {
	_, err := db.Collections["orgs"].UpdateDocument(ctx, org.Key, org)
	return err
}
