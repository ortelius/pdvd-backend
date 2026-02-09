package api

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/graphql"
	"github.com/ortelius/pdvd-backend/v12/restapi"
)

// NewFiberApp creates and configures a Fiber app with REST and GraphQL routes
func NewFiberApp(db database.DBConnection) *fiber.App {
	// Initialize GraphQL schema
	graphql.InitDB(db)
	schema, err := graphql.CreateSchema()
	if err != nil {
		log.Fatalf("Failed to create GraphQL schema: %v", err)
	}

	app := fiber.New(fiber.Config{
		AppName:     "pdvd-backend/v12 API v1.0",
		BodyLimit:   50 * 1024 * 1024, // 50MB
		ReadTimeout: 60 * time.Second, // seconds
	})

	// Middleware
	app.Use(fiberrecover.New())
	app.Use(compress.New(compress.Config{Level: compress.LevelBestSpeed}))

	// Consolidated CORS Configuration
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://localhost:4000,http://127.0.0.1:3000,http://127.0.0.1:4000",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With",
		AllowCredentials: true,
		AllowMethods:     "GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS",
	}))

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("graphql_op", "-")
		return c.Next()
	})
	app.Use(logger.New())

	// Health check endpoint
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	// Setup REST and GraphQL routes (Pass the schema here)
	restapi.SetupRoutes(app, db, schema)

	return app
}
