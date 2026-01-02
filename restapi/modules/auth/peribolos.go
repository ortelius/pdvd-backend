// Package auth provides Peribolos-style RBAC configuration management.
package auth

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"gopkg.in/yaml.v2"
)

// PeriobolosConfig represents the YAML structure
type PeriobolosConfig struct {
	Users []PeriobolosUser `yaml:"users"`
	Roles map[string]struct {
		Description string   `yaml:"description"`
		Permissions []string `yaml:"permissions"`
	} `yaml:"roles,omitempty"`
}

// PeriobolosUser represents a user in the config
type PeriobolosUser struct {
	Username     string `yaml:"username"`
	Email        string `yaml:"email"`
	Role         string `yaml:"role"`
	IsActive     bool   `yaml:"is_active"`
	AuthProvider string `yaml:"auth_provider"`
	ExternalID   string `yaml:"external_id,omitempty"`
}

// RBACResult tracks the outcome of an RBAC apply operation
type RBACResult struct {
	Created     []string
	Updated     []string
	Removed     []string
	Invited     []string // Users who were sent invitations
	Errors      []string
	Invitations map[string]string // username -> invitation link
}

// LoadPeriobolosConfig reads and parses the rbac.yaml file
func LoadPeriobolosConfig(filepath string) (*PeriobolosConfig, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config PeriobolosConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, nil
}

// validateConfig ensures the configuration is valid
func validateConfig(config *PeriobolosConfig) error {
	validRoles := map[string]bool{"admin": true, "editor": true, "viewer": true}
	validAuthProviders := map[string]bool{"local": true, "oidc": true}

	seenUsernames := make(map[string]bool)
	seenEmails := make(map[string]bool)

	for _, user := range config.Users {
		if user.Username == "" {
			return fmt.Errorf("username is required")
		}
		if user.Email == "" {
			return fmt.Errorf("email is required for user %s", user.Username)
		}
		if user.Role == "" {
			return fmt.Errorf("role is required for user %s", user.Username)
		}

		if seenUsernames[user.Username] {
			return fmt.Errorf("duplicate username: %s", user.Username)
		}
		seenUsernames[user.Username] = true

		if seenEmails[user.Email] {
			return fmt.Errorf("duplicate email: %s", user.Email)
		}
		seenEmails[user.Email] = true

		if !validRoles[user.Role] {
			return fmt.Errorf("invalid role '%s' for user %s", user.Role, user.Username)
		}

		if user.AuthProvider == "" {
			user.AuthProvider = "local"
		}
		if !validAuthProviders[user.AuthProvider] {
			return fmt.Errorf("invalid auth_provider '%s'", user.AuthProvider)
		}
	}
	return nil
}

// ApplyRBAC reconciles the database with the YAML configuration
func ApplyRBAC(db database.DBConnection, config *PeriobolosConfig, emailConfig *EmailConfig) (*RBACResult, error) {
	ctx := context.Background()
	result := &RBACResult{
		Created:     []string{},
		Updated:     []string{},
		Removed:     []string{},
		Invited:     []string{},
		Errors:      []string{},
		Invitations: make(map[string]string),
	}

	existingUsers, err := getAllUsers(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch users: %w", err)
	}

	existingUserMap := make(map[string]model.User)
	for _, user := range existingUsers {
		existingUserMap[user.Username] = user
	}

	configUsernames := make(map[string]bool)
	for _, configUser := range config.Users {
		configUsernames[configUser.Username] = true

		if existingUser, exists := existingUserMap[configUser.Username]; exists {
			if err := updateUserFromConfig(ctx, db, existingUser, configUser, result); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to update %s: %v", configUser.Username, err))
			}
		} else {
			invitationLink, err := createUserWithInvitation(ctx, db, emailConfig, configUser)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to create %s: %v", configUser.Username, err))
			} else {
				result.Created = append(result.Created, configUser.Username)

				// FIX A: Only add to Invited list if a link (token) was generated
				if invitationLink != "" {
					result.Invited = append(result.Invited, configUser.Username)
					result.Invitations[configUser.Username] = invitationLink
				}
			}
		}
	}

	for username := range existingUserMap {
		if username == "admin" {
			continue
		}
		if !configUsernames[username] {
			if err := removeUser(ctx, db, username); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to remove %s: %v", username, err))
			} else {
				result.Removed = append(result.Removed, username)
			}
		}
	}

	return result, nil
}

// getAllUsers fetches all users from the database
func getAllUsers(ctx context.Context, db database.DBConnection) ([]model.User, error) {
	query := `FOR u IN users RETURN u`
	cursor, err := db.Database.Query(ctx, query, nil)
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var users []model.User
	for cursor.HasMore() {
		var user model.User
		if _, err := cursor.ReadDocument(ctx, &user); err == nil {
			users = append(users, user)
		}
	}
	return users, nil
}

// createUserWithInvitation creates a new user in pending state and sends invitation
func createUserWithInvitation(ctx context.Context, db database.DBConnection, emailConfig *EmailConfig, configUser PeriobolosUser) (string, error) {
	user := model.NewUser(configUser.Username, configUser.Role)
	user.Email = configUser.Email
	user.IsActive = configUser.IsActive
	user.Status = "pending"
	user.AuthProvider = configUser.AuthProvider
	user.ExternalID = configUser.ExternalID

	_, err := db.Collections["users"].CreateDocument(ctx, user)
	if err != nil {
		return "", err
	}

	var invitationLink string
	if configUser.AuthProvider == "local" {
		invitation, err := CreateInvitation(ctx, db, emailConfig, configUser.Username, configUser.Email, configUser.Role)
		if err != nil {
			return "", fmt.Errorf("failed to create invitation: %w", err)
		}
		invitationLink = fmt.Sprintf("%s/invitation/%s", emailConfig.BaseURL, invitation.Token)
	} else {
		// OIDC users don't need invitations - activate immediately
		updateQuery := `FOR u IN users FILTER u.username == @username UPDATE u WITH {status: "active"} IN users`
		_, err = db.Database.Query(ctx, updateQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{"username": configUser.Username},
		})
		if err != nil {
			return "", err
		}
	}

	return invitationLink, nil
}

// updateUserFromConfig updates an existing user if changes detected
func updateUserFromConfig(ctx context.Context, db database.DBConnection, existingUser model.User, configUser PeriobolosUser, result *RBACResult) error {
	needsUpdate := false
	updateFields := make(map[string]interface{})
	updateFields["updated_at"] = time.Now()

	if existingUser.Email != configUser.Email {
		updateFields["email"] = configUser.Email
		needsUpdate = true
	}
	if existingUser.Role != configUser.Role {
		updateFields["role"] = configUser.Role
		needsUpdate = true
	}
	if existingUser.IsActive != configUser.IsActive {
		updateFields["is_active"] = configUser.IsActive
		needsUpdate = true
	}
	if existingUser.AuthProvider != configUser.AuthProvider {
		updateFields["auth_provider"] = configUser.AuthProvider
		needsUpdate = true
	}
	if configUser.ExternalID != "" && existingUser.ExternalID != configUser.ExternalID {
		updateFields["external_id"] = configUser.ExternalID
		needsUpdate = true
	}

	if needsUpdate {
		query := `FOR u IN users FILTER u.username == @username UPDATE u WITH @fields IN users`
		_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"username": configUser.Username,
				"fields":   updateFields,
			},
		})
		if err != nil {
			return err
		}
		result.Updated = append(result.Updated, configUser.Username)
	}
	return nil
}

// removeUser removes a user from the database
func removeUser(ctx context.Context, db database.DBConnection, username string) error {
	query := `FOR u IN users FILTER u.username == @username REMOVE u IN users`
	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"username": username},
	})
	return err
}
