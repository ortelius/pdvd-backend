// Package auth provides authentication and authorization types for the REST API.
package auth

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
)

// Login handles the username/password exchange
func Login(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		ctx := context.Background()

		// 1. Fetch User
		query := `FOR u IN users FILTER u.username == @username LIMIT 1 RETURN u`
		cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{"username": req.Username},
		})

		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}
		defer cursor.Close()

		var user model.User
		if !cursor.HasMore() {
			// No user found
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		if _, err := cursor.ReadDocument(ctx, &user); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		// 2. Validate Password & Status
		if !user.IsActive {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Account is disabled"})
		}

		if !CheckPasswordHash(req.Password, user.PasswordHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		// 3. Generate Token
		token, err := GenerateJWT(user.Username, user.Role)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate session"})
		}

		// 4. Set HttpOnly Cookie
		cookie := new(fiber.Cookie)
		cookie.Name = "auth_token"
		cookie.Value = token
		cookie.Expires = time.Now().Add(24 * time.Hour)
		cookie.HTTPOnly = true
		cookie.Secure = true // Essential for GLB/SSL
		cookie.SameSite = "Lax"
		c.Cookie(cookie)

		return c.JSON(UserResponse{
			Username: user.Username,
			Role:     user.Role,
		})
	}
}

// Logout clears the session cookie
func Logout(c *fiber.Ctx) error {
	cookie := new(fiber.Cookie)
	cookie.Name = "auth_token"
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-1 * time.Hour) // Expire immediately
	cookie.HTTPOnly = true
	c.Cookie(cookie)
	return c.JSON(fiber.Map{"message": "Logged out"})
}

// Me returns the current user info from the session cookie
func Me(c *fiber.Ctx) error {
	token := c.Cookies("auth_token")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Not logged in"})
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid session"})
	}

	return c.JSON(UserResponse{
		Username: claims["sub"].(string),
		Role:     claims["role"].(string),
	})
}

// ForgotPassword is a placeholder for the invite/reset logic
func ForgotPassword(_ database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req ForgotPasswordRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		// NOTE: In a real implementation, you would:
		// 1. Look up user by email
		// 2. Generate a reset token
		// 3. Send email via SMTP/SendGrid

		log.Printf("Password reset requested for: %s", req.Email)

		// Always return success to prevent email enumeration
		return c.JSON(fiber.Map{"message": "If that email exists, a reset link has been sent."})
	}
}

// BootstrapAdmin implements the "K8s Log Token" pattern
// It continues to rotate/show the admin token until a second user is created.
func BootstrapAdmin(db database.DBConnection) {
	ctx := context.Background()

	// 1. Check User Count
	// We only stop bootstrapping if there are > 1 users (e.g. Admin + 1 Real User)
	query := `RETURN LENGTH(users)`
	cursor, err := db.Database.Query(ctx, query, nil)
	if err != nil {
		log.Printf("Bootstrap check failed: %v", err)
		return
	}
	defer cursor.Close()

	var userCount int
	if cursor.HasMore() {
		if _, err := cursor.ReadDocument(ctx, &userCount); err != nil {
			log.Printf("Failed to read user count: %v", err)
			return
		}
	}

	if userCount > 1 {
		log.Println("System initialized (multiple users found). Bootstrap disabled.")
		return
	}

	log.Println("Bootstrap mode active (single user detected). Rotating admin token...")

	// 2. Generate secure token
	token, err := GenerateRandomString(32)
	if err != nil {
		cursor.Close()
		log.Printf("Failed to generate bootstrap token: %v", err)
		return
	}

	// 3. Upsert the bootstrap user (Create if missing, Update password if exists)
	hash, _ := HashPassword(token)
	adminUser := model.NewUser("admin", "admin")
	adminUser.PasswordHash = hash
	adminUser.Email = "admin@localhost"

	// Using AQL UPSERT to handle both creation and password rotation in one atomic op
	upsertQuery := `
		UPSERT { username: "admin" }
		INSERT @adminUser
		UPDATE { password_hash: @hash, updated_at: @now, is_active: true } IN users
	`

	_, err = db.Database.Query(ctx, upsertQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"adminUser": adminUser,
			"hash":      hash,
			"now":       time.Now(),
		},
	})

	if err != nil {
		log.Fatalf("Failed to upsert bootstrap admin: %v", err)
	}

	// 4. LOG TO STDOUT (This goes to K8s logs)
	// Uses padding to ensure exact 60-char box width
	// "* " (2 chars) + Content (56 chars) + " *" (2 chars) = 60 chars
	const contentWidth = 56

	fmt.Println("************************************************************")
	fmt.Printf("* %-*s *\n", contentWidth, "ORTELIUS INITIAL ADMIN TOKEN")
	fmt.Printf("* %-*s *\n", contentWidth, "")
	fmt.Printf("* %-*s *\n", contentWidth, "User:  admin")
	fmt.Printf("* %-*s *\n", contentWidth, fmt.Sprintf("Token: %s", token))
	fmt.Printf("* %-*s *\n", contentWidth, "")
	fmt.Printf("* %-*s *\n", contentWidth, "Use this to log in and configure your RBAC policies.")
	fmt.Println("************************************************************")
}
