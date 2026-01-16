// package main provides the entry point and API handlers for the pdvd-backend/v12 microservice.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/graphql-go/graphql"
	"github.com/ortelius/pdvd-backend/v12/database"
	gqlschema "github.com/ortelius/pdvd-backend/v12/graphql"
	"github.com/ortelius/pdvd-backend/v12/restapi"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/auth"
)

var db database.DBConnection

// GraphQLHandler handles GraphQL requests
func GraphQLHandler(schema graphql.Schema) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var params struct {
			Query         string                 `json:"query"`
			OperationName string                 `json:"operationName"`
			Variables     map[string]interface{} `json:"variables"`
		}

		if err := c.BodyParser(&params); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"errors": []map[string]interface{}{
					{
						"message": "Invalid request body",
					},
				},
			})
		}

		// Set Operation Name for Logger
		opName := params.OperationName
		if opName == "" {
			opName = "-"
		}
		c.Locals("graphql_op", opName)

		// Create a standard context for GraphQL
		ctx := context.Background()

		// Extract user info from Fiber Locals (set by OptionalAuth middleware)
		// and inject it into the GraphQL context using SHARED auth keys
		if username, ok := c.Locals("username").(string); ok {
			ctx = context.WithValue(ctx, auth.UserKey, username)
		}
		if role, ok := c.Locals("role").(string); ok {
			ctx = context.WithValue(ctx, auth.RoleKey, role)
		}
		if orgs, ok := c.Locals("orgs").([]string); ok {
			ctx = context.WithValue(ctx, auth.OrgsKey, orgs)
		}

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  params.Query,
			VariableValues: params.Variables,
			OperationName:  params.OperationName,
			Context:        ctx, // Pass the authenticated context
		})

		if len(result.Errors) > 0 {
			log.Printf("GraphQL errors: %v", result.Errors)
		}

		return c.JSON(result)
	}
}

func main() {
	// Initialize database connection
	db = database.InitializeDatabase()

	// Initialize GraphQL schema
	gqlschema.InitDB(db)
	schema, err := gqlschema.CreateSchema()
	if err != nil {
		log.Fatalf("Failed to create GraphQL schema: %v", err)
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:     "pdvd-backend/v12 API v1.0",
		BodyLimit:   50 * 1024 * 1024, // 50MB limit for SBOM uploads
		ReadTimeout: time.Second * 60, // 60 second read timeout for large uploads
	})

	// Middleware
	app.Use(fiberrecover.New())
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))

	// Default GraphQL Operation Name to "-" to handle OPTIONS/other requests gracefully
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("graphql_op", "-")
		return c.Next()
	})

	// Custom Logger Config to include GraphQL Operation Name
	app.Use(logger.New(logger.Config{
		Format: "${time} | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${locals:graphql_op} | ${error}\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://localhost:4000,http://127.0.0.1:3000,http://127.0.0.1:4000",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Requested-With",
		AllowCredentials: true, // Required for cookies to be accepted
		AllowMethods:     "GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS",
	}))

	// Health check endpoint
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
		})
	})

	// Setup REST API routes (modular)
	restapi.SetupRoutes(app, db)

	// GraphQL endpoint
	// Apply OptionalAuth middleware to process the HttpOnly cookie and populate context
	app.Post("/api/v1/graphql", auth.OptionalAuth(db), GraphQLHandler(schema))

	// Get port from environment or default to 3000
	port := os.Getenv("MS_PORT")
	if port == "" {
		port = "3000"
	}

	// Start server
	log.Printf("Starting server on port %s", port)
	log.Printf("REST API endpoints available at /api/v1/*")
	log.Printf("GraphQL endpoint available at /api/v1/graphql")
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
