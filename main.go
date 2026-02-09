package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/internal/api"
	"github.com/ortelius/pdvd-backend/v12/internal/kafka"
)

func main() {
	db := database.InitializeDatabase()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Attempt to start Kafka (Optional)
	if err := kafka.RunEventProcessor(ctx, db); err != nil {
		log.Printf("Warning: Kafka initialization failed after 3 tries: %v. Starting without Kafka support.", err)
	} else {
		log.Println("Kafka processor initialized successfully.")
	}

	// Start everything else normally
	app := api.NewFiberApp(db)
	port := os.Getenv("MS_PORT")
	if port == "" {
		port = "3000"
	}

	go func() {
		log.Printf("Starting server on port %s", port)
		if err := app.Listen(":" + port); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down pdvd-backend...")
	app.Shutdown()
}
