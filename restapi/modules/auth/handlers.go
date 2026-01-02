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

// SetAuthCookie configures and sets the JWT session cookie in the Fiber context
func SetAuthCookie(c *fiber.Ctx, token string) {
	cookie := new(fiber.Cookie)
	cookie.Name = "auth_token"
	cookie.Value = token
	cookie.Expires = time.Now().Add(24 * time.Hour)
	cookie.HTTPOnly = true
	cookie.Secure = true // Essential for GLB/SSL
	cookie.SameSite = "Lax"
	c.Cookie(cookie)
}

// Login handles the username/password exchange
func Login(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		ctx := context.Background()

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
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		if _, err := cursor.ReadDocument(ctx, &user); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		if !user.IsActive {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Account is disabled"})
		}

		if !CheckPasswordHash(req.Password, user.PasswordHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		token, err := GenerateJWT(user.Username, user.Role)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate session"})
		}

		// Use helper for consistent cookie configuration
		SetAuthCookie(c, token)

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
	cookie.Expires = time.Now().Add(-1 * time.Hour)
	cookie.HTTPOnly = true
	c.Cookie(cookie)
	return c.JSON(fiber.Map{"message": "Logged out"})
}

// Me returns current user info
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

// ForgotPassword request handler
func ForgotPassword(_ database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req ForgotPasswordRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}
		log.Printf("Password reset requested for: %s", req.Email)
		return c.JSON(fiber.Map{"message": "If that email exists, a reset link has been sent."})
	}
}

// BootstrapAdmin handles initial system setup
func BootstrapAdmin(db database.DBConnection) {
	ctx := context.Background()
	query := `RETURN LENGTH(users)`
	cursor, err := db.Database.Query(ctx, query, nil)
	if err != nil {
		return
	}
	defer cursor.Close()

	var userCount int
	if cursor.HasMore() {
		cursor.ReadDocument(ctx, &userCount)
	}
	if userCount > 1 {
		return
	}

	token, _ := GenerateRandomString(32)
	hash, _ := HashPassword(token)
	adminUser := model.NewUser("admin", "admin")
	adminUser.PasswordHash = hash
	adminUser.Email = "admin@localhost"

	upsertQuery := `
		UPSERT { username: "admin" }
		INSERT @adminUser
		UPDATE { password_hash: @hash, updated_at: @now, is_active: true } IN users
	`
	db.Database.Query(ctx, upsertQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"adminUser": adminUser, "hash": hash, "now": time.Now()},
	})

	fmt.Printf("\n************************************************************\n")
	fmt.Printf("* ORTELIUS INITIAL ADMIN TOKEN: %s\n", token)
	fmt.Printf("************************************************************\n\n")
}
