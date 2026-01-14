// Package auth provides authentication handlers for Fiber.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/gitops"
)

// ============================================================================
// AUTH HANDLERS
// ============================================================================

// Signup handles public user registration requests via GitOps flow
func Signup(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Username     string `json:"username"`
			Email        string `json:"email"`
			FirstName    string `json:"first_name"`
			LastName     string `json:"last_name"`
			Organization string `json:"organization"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		// Validation
		if req.Username == "" || req.Email == "" || req.FirstName == "" || req.LastName == "" || req.Organization == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "All fields are required",
			})
		}

		ctx := c.Context()

		// 1. Check if Username or Email already exists (Case-Insensitive)
		userCheckQuery := `
			FOR u IN users 
			FILTER LOWER(u.username) == LOWER(@username) OR LOWER(u.email) == LOWER(@email)
			LIMIT 1
			RETURN u
		`
		userCursor, err := db.Database.Query(ctx, userCheckQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"username": req.Username,
				"email":    req.Email,
			},
		})
		if err == nil {
			defer userCursor.Close()
			if userCursor.HasMore() {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{
					"error": "Username or Email is already in use",
				})
			}
		}

		// 2. Check if Organization Exists (Case-Insensitive)
		var existingOrgName string
		orgCheckQuery := `
			FOR o IN orgs 
			FILTER LOWER(o.name) == LOWER(@org)
			LIMIT 1
			RETURN o.name
		`
		orgCursor, err := db.Database.Query(ctx, orgCheckQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"org": req.Organization,
			},
		})

		if err == nil {
			defer orgCursor.Close()
			if orgCursor.HasMore() {
				// Organization exists - Read the actual name
				orgCursor.ReadDocument(ctx, &existingOrgName)

				// Attempt to find the owner/admin email for this organization
				adminEmail, err := getOrgAdminEmail(ctx, db, existingOrgName)

				msg := fmt.Sprintf("Organization '%s' already exists.", existingOrgName)
				if err == nil && adminEmail != "" {
					msg += fmt.Sprintf(" Please contact the organization administrator at %s to join.", adminEmail)
				} else {
					msg += " Please contact the organization administrator to join."
				}

				return c.Status(fiber.StatusConflict).JSON(fiber.Map{
					"error": msg,
				})
			}
		}

		// 3. Execute GitOps Workflow
		updatedYaml, err := gitops.UpdateRBACRepo(req.Username, req.Email, req.FirstName, req.LastName, req.Organization)
		if err != nil {
			fmt.Printf("GitOps Error: %v\n", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to process signup request. Please try again later.",
			})
		}

		// 4. Apply the Configuration Locally
		config, err := LoadPeriobolosConfig(updatedYaml)
		if err != nil {
			fmt.Printf("Config Load Error: %v\n", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal configuration error",
			})
		}

		result, err := ApplyRBAC(db, config, emailConfig)
		if err != nil {
			fmt.Printf("RBAC Sync Error: %v\n", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to apply account configuration",
			})
		}

		fmt.Printf("Signup Complete for %s. Created: %v, Invited: %v\n", req.Username, result.Created, result.Invited)

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"success": true,
			"message": "Signup request processed. Configuration updated and invitation sent.",
		})
	}
}

// getOrgAdminEmail finds the email of a user in the org to contact.
// Prioritizes 'owner', then 'admin', then 'editor', then 'viewer'.
func getOrgAdminEmail(ctx context.Context, db database.DBConnection, orgName string) (string, error) {
	query := `
		FOR u IN users
			FILTER @orgName IN u.orgs
			LET score = u.role == 'owner' ? 0 : u.role == 'admin' ? 1 : u.role == 'editor' ? 2 : 3
			SORT score ASC
			LIMIT 1
			RETURN u.email
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"orgName": orgName},
	})
	if err != nil {
		return "", err
	}
	defer cursor.Close()

	var email string
	if cursor.HasMore() {
		_, err := cursor.ReadDocument(ctx, &email)
		return email, err
	}
	return "", fmt.Errorf("no user found for org")
}

// Login handles user login and sets auth cookie
func Login(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if req.Username == "" || req.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Username and password are required",
			})
		}

		ctx := c.Context()
		user, err := getUserByUsername(ctx, db, req.Username)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid credentials",
			})
		}

		if !user.IsActive {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Account is inactive",
			})
		}

		if !CheckPasswordHash(req.Password, user.PasswordHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid credentials",
			})
		}

		// UPDATED: Only pass username to GenerateJWT
		token, err := GenerateJWT(user.Username)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to generate token",
			})
		}

		SetAuthCookie(c, token)

		return c.JSON(fiber.Map{
			"message":  "Login successful",
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
			"orgs":     user.Orgs,
		})
	}
}

// Logout clears the auth cookie
func Logout() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.ClearCookie("auth_token")
		return c.JSON(fiber.Map{
			"message": "Logged out successfully",
		})
	}
}

// Me returns current authenticated user info
func Me(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get username from validated JWT claim (via middleware)
		username, ok := c.Locals("username").(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Not authenticated",
			})
		}

		// Fetch fresh user data from DB to ensure orgs/roles/email are up to date
		ctx := c.Context()
		user, err := getUserByUsername(ctx, db, username)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch user profile",
			})
		}

		return c.JSON(fiber.Map{
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
			"orgs":     user.Orgs,
		})
	}
}

// ForgotPassword handles password reset requests
func ForgotPassword(_ database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req ForgotPasswordRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		// TODO: Implement password reset logic with email
		return c.JSON(fiber.Map{
			"message": "Password reset email sent (not implemented yet)",
		})
	}
}

// ChangePassword handles password change for authenticated users
func ChangePassword(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		username, ok := c.Locals("username").(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
			})
		}

		var req struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if err := ValidatePasswordStrength(req.NewPassword); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		ctx := c.Context()
		user, err := getUserByUsername(ctx, db, username)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to get user",
			})
		}

		if !CheckPasswordHash(req.OldPassword, user.PasswordHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid old password",
			})
		}

		newHash, err := HashPassword(req.NewPassword)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to hash password",
			})
		}

		user.PasswordHash = newHash
		user.UpdatedAt = time.Now()

		if err := updateUser(ctx, db, user); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to update password",
			})
		}

		return c.JSON(fiber.Map{
			"message": "Password changed successfully",
		})
	}
}

// RefreshToken refreshes JWT token
func RefreshToken(_ database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		oldToken := c.Cookies("auth_token")
		if oldToken == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "No token to refresh",
			})
		}

		newToken, err := RefreshJWT(oldToken)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		SetAuthCookie(c, newToken)

		return c.JSON(fiber.Map{
			"message": "Token refreshed successfully",
		})
	}
}

// ============================================================================
// USER MANAGEMENT HANDLERS (Admin only)
// ============================================================================

// ListUsers lists all users
func ListUsers(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.Context()
		users, err := listUsers(ctx, db)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to list users",
			})
		}

		userList := make([]fiber.Map, len(users))
		for i, user := range users {
			userList[i] = fiber.Map{
				"username":  user.Username,
				"email":     user.Email,
				"role":      user.Role,
				"orgs":      user.Orgs,
				"is_active": user.IsActive,
				"status":    user.Status,
			}
		}

		return c.JSON(fiber.Map{
			"users": userList,
			"total": len(userList),
		})
	}
}

// CreateUser creates a new user
func CreateUser(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Username string   `json:"username"`
			Email    string   `json:"email"`
			Password string   `json:"password"`
			Role     string   `json:"role"`
			Orgs     []string `json:"orgs"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if req.Username == "" || req.Email == "" || req.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Username, email, and password are required",
			})
		}

		if err := ValidatePasswordStrength(req.Password); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if req.Role != "owner" && req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid role. Must be owner, admin, editor, or viewer",
			})
		}

		ctx := c.Context()
		if _, err := getUserByUsername(ctx, db, req.Username); err == nil {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Username already exists",
			})
		}

		passwordHash, err := HashPassword(req.Password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to hash password",
			})
		}

		user := model.NewUser(req.Username, req.Role)
		user.Email = req.Email
		user.PasswordHash = passwordHash
		user.Orgs = req.Orgs
		user.IsActive = true
		user.Status = "active"

		if err := createUser(ctx, db, user); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create user",
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "User created successfully",
			"user": fiber.Map{
				"username": user.Username,
				"email":    user.Email,
				"role":     user.Role,
				"orgs":     user.Orgs,
			},
		})
	}
}

// GetUser retrieves a user by username
func GetUser(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		username := c.Params("username")
		ctx := c.Context()

		user, err := getUserByUsername(ctx, db, username)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}

		return c.JSON(fiber.Map{
			"user": fiber.Map{
				"username":  user.Username,
				"email":     user.Email,
				"role":      user.Role,
				"orgs":      user.Orgs,
				"is_active": user.IsActive,
				"status":    user.Status,
			},
		})
	}
}

// UpdateUser updates a user
func UpdateUser(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		username := c.Params("username")

		var req struct {
			Email    string   `json:"email"`
			Role     string   `json:"role"`
			Orgs     []string `json:"orgs"`
			IsActive *bool    `json:"is_active"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		ctx := c.Context()
		user, err := getUserByUsername(ctx, db, username)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}

		if req.Email != "" {
			user.Email = req.Email
		}
		if req.Role != "" {
			if req.Role != "owner" && req.Role != "admin" && req.Role != "editor" && req.Role != "viewer" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Invalid role",
				})
			}
			user.Role = req.Role
		}
		if req.Orgs != nil {
			user.Orgs = req.Orgs
		}
		if req.IsActive != nil {
			user.IsActive = *req.IsActive
		}
		user.UpdatedAt = time.Now()

		if err := updateUser(ctx, db, user); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to update user",
			})
		}

		return c.JSON(fiber.Map{
			"message": "User updated successfully",
			"user": fiber.Map{
				"username":  user.Username,
				"email":     user.Email,
				"role":      user.Role,
				"orgs":      user.Orgs,
				"is_active": user.IsActive,
			},
		})
	}
}

// DeleteUser deletes a user
func DeleteUser(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		username := c.Params("username")

		currentUser, ok := c.Locals("username").(string)
		if ok && currentUser == username {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Cannot delete your own account",
			})
		}

		ctx := c.Context()
		if err := deleteUser(ctx, db, username); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to delete user",
			})
		}

		return c.JSON(fiber.Map{
			"message": "User deleted successfully",
		})
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// SetAuthCookie sets the auth token cookie in the Fiber context.
// UPDATED: Added Path="/" and SameSite="Lax" to ensure cross-port localhost compatibility
func SetAuthCookie(c *fiber.Ctx, token string) {
	c.Cookie(&fiber.Cookie{
		Name:     "auth_token",
		Value:    token,
		HTTPOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: "Lax",
		MaxAge:   86400, // 24 hours
		Path:     "/",   // Ensure cookie is valid for entire domain
	})
}

// getUserByUsername retrieves a user from the database
func getUserByUsername(ctx context.Context, db database.DBConnection, username string) (*model.User, error) {
	query := `FOR u IN users FILTER u.username == @username RETURN u`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"username": username},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var user model.User
	if _, err := cursor.ReadDocument(ctx, &user); err != nil {
		return nil, fmt.Errorf("user not found")
	}

	return &user, nil
}

// createUser creates a new user in the database
func createUser(ctx context.Context, db database.DBConnection, user *model.User) error {
	query := `
		INSERT {
			username: @username,
			email: @email,
			password_hash: @password_hash,
			role: @role,
			orgs: @orgs,
			is_active: @is_active,
			status: @status,
			auth_provider: @auth_provider,
			created_at: @created_at,
			updated_at: @updated_at
		} INTO users
	`

	bindVars := map[string]interface{}{
		"username":      user.Username,
		"email":         user.Email,
		"password_hash": user.PasswordHash,
		"role":          user.Role,
		"orgs":          user.Orgs,
		"is_active":     user.IsActive,
		"status":        user.Status,
		"auth_provider": user.AuthProvider,
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
	}

	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	return err
}

// updateUser updates an existing user in the database
func updateUser(ctx context.Context, db database.DBConnection, user *model.User) error {
	query := `
		FOR u IN users
		FILTER u.username == @username
		UPDATE u WITH {
			email: @email,
			password_hash: @password_hash,
			role: @role,
			orgs: @orgs,
			is_active: @is_active,
			status: @status,
			updated_at: @updated_at
		} IN users
	`

	bindVars := map[string]interface{}{
		"username":      user.Username,
		"email":         user.Email,
		"password_hash": user.PasswordHash,
		"role":          user.Role,
		"orgs":          user.Orgs,
		"is_active":     user.IsActive,
		"status":        user.Status,
		"updated_at":    user.UpdatedAt,
	}

	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	return err
}

// deleteUser deletes a user from the database
func deleteUser(ctx context.Context, db database.DBConnection, username string) error {
	query := `FOR u IN users FILTER u.username == @username REMOVE u IN users`
	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"username": username},
	})
	return err
}

// listUsers retrieves all users from the database
func listUsers(ctx context.Context, db database.DBConnection) ([]*model.User, error) {
	query := `FOR u IN users RETURN u`
	cursor, err := db.Database.Query(ctx, query, nil)
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var users []*model.User
	for cursor.HasMore() {
		var user model.User
		if _, err := cursor.ReadDocument(ctx, &user); err == nil {
			users = append(users, &user)
		}
	}

	return users, nil
}

// GenerateRandomString generates a secure cryptographically random string for tokens.
func GenerateRandomString(length int) (string, error) {
	return GenerateSecureToken(length)
}
