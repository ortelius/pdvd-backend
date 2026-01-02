package auth

import (
	"github.com/gofiber/fiber/v2"
)

// RequireAuth middleware validates JWT token from cookie and blocks guests
func RequireAuth(c *fiber.Ctx) error {
	token := c.Cookies("auth_token")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired session",
		})
	}

	// Store user info in context
	c.Locals("is_authenticated", true)
	c.Locals("username", claims["sub"].(string))
	c.Locals("role", claims["role"].(string))

	return c.Next()
}

// OptionalAuth identifies the user if a token is present but does not block guests.
// This allows a single endpoint to serve both public and private data based on status.
func OptionalAuth(c *fiber.Ctx) error {
	token := c.Cookies("auth_token")
	if token == "" {
		c.Locals("is_authenticated", false)
		return c.Next()
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		// Treat invalid/expired tokens as guest access
		c.Locals("is_authenticated", false)
		return c.Next()
	}

	// User is authenticated; set context for handlers
	c.Locals("is_authenticated", true)
	c.Locals("username", claims["sub"].(string))
	c.Locals("role", claims["role"].(string))

	return c.Next()
}

// RequireRole middleware checks if user has one of the required roles
func RequireRole(allowedRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userRole, ok := c.Locals("role").(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
			})
		}

		for _, role := range allowedRoles {
			if userRole == role {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Insufficient permissions",
		})
	}
}
