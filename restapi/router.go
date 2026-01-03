// Package restapi provides the main router and initialization for REST API endpoints.
package restapi

import (
	"context"
	"fmt"
	"log"
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
	// Bootstrap admin user on startup (only runs if no users exist)
	go func() {
		if err := auth.BootstrapAdmin(db); err != nil {
			log.Printf("WARNING: Failed to bootstrap admin: %v", err)
		}
	}()

	// Ensure default roles exist
	go func() {
		if err := auth.EnsureDefaultRoles(db); err != nil {
			log.Printf("WARNING: Failed to ensure default roles: %v", err)
		}
	}()

	// Load email configuration for invitations
	emailConfig := auth.LoadEmailConfig()

	// Auto-apply RBAC from disk if configured
	go autoApplyRBACOnStartup(db, emailConfig)

	// Start background cleanup of expired invitations
	go startInvitationCleanup(db)

	// API group
	api := app.Group("/api/v1")

	// ========================================================================
	// AUTH ENDPOINTS (Public)
	// ========================================================================
	authGroup := api.Group("/auth")
	authGroup.Post("/login", auth.Login(db))
	authGroup.Post("/logout", auth.Logout)
	authGroup.Get("/me", auth.Me)
	authGroup.Post("/forgot-password", auth.ForgotPassword(db))
	authGroup.Post("/change-password", auth.ChangePassword(db))
	authGroup.Post("/refresh", auth.RefreshToken(db))

	// ========================================================================
	// INVITATION ENDPOINTS (Public)
	// ========================================================================
	invitationGroup := api.Group("/invitation")
	invitationGroup.Get("/:token", auth.GetInvitationHandler(db))
	invitationGroup.Post("/:token/accept", auth.AcceptInvitationHandler(db))
	invitationGroup.Post("/:token/resend", auth.ResendInvitationHandler(db, emailConfig))

	// ========================================================================
	// USER MANAGEMENT ENDPOINTS (Admin only)
	// ========================================================================
	userGroup := api.Group("/users", auth.RequireAuth, auth.RequireRole("admin"))
	userGroup.Get("/", auth.ListUsers(db))
	userGroup.Post("/", auth.CreateUser(db))
	userGroup.Get("/:username", auth.GetUser(db))
	userGroup.Put("/:username", auth.UpdateUser(db))
	userGroup.Delete("/:username", auth.DeleteUser(db))

	// ========================================================================
	// RBAC MANAGEMENT ENDPOINTS (Admin only)
	// ========================================================================
	rbac := api.Group("/rbac", auth.RequireAuth, auth.RequireRole("admin"))
	rbac.Post("/apply/content", auth.ApplyRBACFromBody(db, emailConfig))
	rbac.Post("/apply/upload", auth.ApplyRBACFromUpload(db, emailConfig))
	rbac.Post("/apply", auth.ApplyRBACFromFile(db, emailConfig))
	rbac.Get("/config", auth.GetRBACConfig(db))
	rbac.Get("/invitations", auth.ListPendingInvitationsHandler(db))

	// ========================================================================
	// RELEASE ENDPOINTS (Supports both guest and authenticated calls)
	// ========================================================================
	api.Post("/releases", auth.OptionalAuth, releases.PostReleaseWithSBOM(db))

	// ========================================================================
	// SYNC ENDPOINTS (Supports both guest and authenticated calls)
	// ========================================================================
	api.Post("/sync", auth.OptionalAuth, sync.PostSyncWithEndpoint(db))

	log.Println("API routes initialized successfully")
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
