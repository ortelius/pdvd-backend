// Package restapi provides the main router and initialization for REST API endpoints.
package restapi

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/auth"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/releases"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/sync"
)

// SetupRoutes configures all REST API routes
func SetupRoutes(app *fiber.App, db database.DBConnection) {
	// Load email configuration for invitations
	emailConfig := auth.LoadEmailConfig()

	// 1. Run Background Logic
	go auth.BootstrapAdmin(db)                 // Checks for admin, creates if missing
	go autoApplyRBACOnStartup(db, emailConfig) // Applies RBAC from disk
	go startInvitationCleanup(db)              // Periodically cleans up expired invites

	// API group
	api := app.Group("/api/v1")

	// 2. Auth Endpoints (Public)
	authGroup := api.Group("/auth")
	authGroup.Post("/login", auth.Login(db))
	authGroup.Post("/logout", auth.Logout)
	authGroup.Get("/me", auth.Me)
	authGroup.Post("/forgot-password", auth.ForgotPassword(db))

	// 3. Invitation Endpoints (Public)
	invitationGroup := api.Group("/invitation")
	invitationGroup.Get("/:token", auth.GetInvitationHandler(db))
	invitationGroup.Post("/:token/accept", auth.AcceptInvitationHandler(db))
	invitationGroup.Post("/:token/resend", auth.ResendInvitationHandler(db, emailConfig))

	// Release endpoints (Supports both guest and authenticated calls)
	api.Post("/releases", auth.OptionalAuth, releases.PostReleaseWithSBOM(db))

	// Sync endpoints (Supports both guest and authenticated calls)
	api.Post("/sync", auth.OptionalAuth, sync.PostSyncWithEndpoint(db))

	// 4. RBAC Management Endpoints (Admin Only)
	rbac := api.Group("/rbac", auth.RequireAuth, auth.RequireRole("admin"))
	rbac.Post("/apply/content", auth.ApplyRBACFromBody(db, emailConfig))
	rbac.Post("/apply/upload", auth.ApplyRBACFromUpload(db, emailConfig))
	rbac.Post("/apply", auth.ApplyRBACFromFile(db, emailConfig))
	rbac.Get("/config", auth.GetRBACConfig(db))
	rbac.Get("/invitations", auth.ListPendingInvitationsHandler(db))
}

// startInvitationCleanup runs a background ticker to remove expired invitations
func startInvitationCleanup(db database.DBConnection) {
	// Run immediately on startup
	runCleanup(db)

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		runCleanup(db)
	}
}

// runCleanup executes the database removal logic for expired invitations
func runCleanup(db database.DBConnection) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	count, err := auth.CleanupExpiredInvitations(ctx, db)
	if err != nil {
		fmt.Printf("⚠️  Background Task: Failed to cleanup expired invitations: %v\n", err)
		return
	}

	if count > 0 {
		fmt.Printf("🧹 Background Task: Cleaned up %d expired invitations\n", count)
	}
}

// autoApplyRBACOnStartup applies RBAC from file if it exists
func autoApplyRBACOnStartup(db database.DBConnection, emailConfig *auth.EmailConfig) {
	configPath := os.Getenv("RBAC_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/pdvd/rbac.yaml"
	}

	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("🔄 Auto-applying RBAC configuration from:", configPath)
		config, err := auth.LoadPeriobolosConfig(configPath)
		if err != nil {
			fmt.Printf("⚠️  Failed to load RBAC config: %v\n", err)
			return
		}

		result, err := auth.ApplyRBAC(db, config, emailConfig)
		if err != nil {
			fmt.Printf("⚠️  RBAC apply failed: %v\n", err)
			return
		}

		fmt.Printf("✅ RBAC apply complete: %d created, %d updated, %d removed, %d invited\n",
			len(result.Created), len(result.Updated), len(result.Removed), len(result.Invited))
	}
}
