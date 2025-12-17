// Package restapi provides the main router and initialization for REST API endpoints.
package restapi

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/admin"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/auth" // ADDED
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/releases"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/sync"
)

// SetupRoutes configures all REST API routes
func SetupRoutes(app *fiber.App, db database.DBConnection) {
	// 1. Run Bootstrap Logic (Checks for admin, creates if missing)
	go auth.BootstrapAdmin(db)

	// API group
	api := app.Group("/api/v1")

	// 2. Auth Endpoints
	authGroup := api.Group("/auth")
	authGroup.Post("/login", auth.Login(db))
	authGroup.Post("/logout", auth.Logout)
	authGroup.Get("/me", auth.Me)
	authGroup.Post("/forgot-password", auth.ForgotPassword(db))

	// Release endpoints
	api.Post("/releases", releases.PostReleaseWithSBOM(db))

	// Sync endpoints
	api.Post("/sync", sync.PostSyncWithEndpoint(db))

	// Admin endpoints
	adminGroup := api.Group("/admin")
	adminGroup.Post("/backfill-mttr", admin.PostBackfillMTTR(db))
	adminGroup.Get("/backfill-status", admin.GetBackfillStatus())
}
