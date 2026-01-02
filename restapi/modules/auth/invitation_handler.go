package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
)

// GetInvitationHandler handles GET /api/v1/invitation/:token
func GetInvitationHandler(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Params("token")
		ctx := c.Context()
		invitation, err := GetInvitation(ctx, db, token)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Invalid or expired invitation"})
		}

		if invitation.IsExpired() || invitation.IsAccepted() {
			return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "Invitation no longer valid"})
		}

		return c.JSON(fiber.Map{
			"username": invitation.Username,
			"email":    invitation.Email,
			"role":     invitation.Role,
		})
	}
}

// AcceptInvitationRequest defines the activation body
type AcceptInvitationRequest struct {
	Password        string `json:"password"`
	PasswordConfirm string `json:"password_confirm"`
}

// AcceptInvitationHandler handles activation and immediate login
func AcceptInvitationHandler(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Params("token")
		var req AcceptInvitationRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid body"})
		}

		if req.Password != req.PasswordConfirm {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Passwords mismatch"})
		}

		ctx := c.Context()
		user, err := AcceptInvitation(ctx, db, token, req.Password)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		// Immediate login after successful activation
		jwtToken, err := GenerateJWT(user.Username, user.Role)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Login failed"})
		}

		// Use helper for consistent cookie configuration
		SetAuthCookie(c, jwtToken)

		return c.JSON(fiber.Map{
			"message":  "Account activated. You are now logged in.",
			"username": user.Username,
		})
	}
}

// ResendInvitationHandler handles POST /api/v1/invitation/:token/resend
func ResendInvitationHandler(db database.DBConnection, emailConfig *EmailConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Params("token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invitation token is required",
			})
		}

		ctx := c.Context()
		err := ResendInvitation(ctx, db, emailConfig, token)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"message": "Invitation email resent successfully",
		})
	}
}

// ListPendingInvitationsHandler handles GET /api/v1/admin/invitations (admin only)
func ListPendingInvitationsHandler(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.Context()

		query := `
			FOR i IN invitations 
			FILTER i.accepted_at == null
			SORT i.created_at DESC
			RETURN {
				username: i.username,
				email: i.email,
				role: i.role,
				created_at: i.created_at,
				expires_at: i.expires_at,
				is_expired: i.expires_at < DATE_NOW(),
				resend_count: i.resend_count
			}
		`
		cursor, err := db.Database.Query(ctx, query, nil)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch invitations",
			})
		}
		defer cursor.Close()

		invitations := []interface{}{}
		for cursor.HasMore() {
			var inv interface{}
			if _, err := cursor.ReadDocument(ctx, &inv); err == nil {
				invitations = append(invitations, inv)
			}
		}

		return c.JSON(fiber.Map{
			"invitations": invitations,
			"count":       len(invitations),
		})
	}
}
