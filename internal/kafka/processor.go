// Package kafka provides Kafka event processing functionality for the PDVD backend.
package kafka

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ortelius/pdvd-backend/v12/database"
	release "github.com/ortelius/pdvd-backend/v12/events/modules/releases"
	"github.com/ortelius/pdvd-backend/v12/internal/services"
	"github.com/segmentio/kafka-go"
)

// RunEventProcessor attempts to connect to Kafka 3 times.
// If successful, it starts the consumer loop. If not, it returns an error.
func RunEventProcessor(ctx context.Context, db database.DBConnection) error {
	brokersEnv := os.Getenv("KAFKA_BROKERS")
	var brokers []string
	if brokersEnv != "" {
		brokers = strings.Split(brokersEnv, ",")
	} else {
		brokers = []string{"localhost:9092"}
	}

	topic := "release-events"
	var conn *kafka.Conn
	var err error

	// Retry logic: 3 tries
	for i := 1; i <= 3; i++ {
		log.Printf("Kafka connection attempt %d/3...", i)
		conn, err = kafka.DialContext(ctx, "tcp", brokers[0])
		if err == nil {
			conn.Close()
			break
		}
		if i < 3 {
			time.Sleep(2 * time.Second)
		}
	}

	if err != nil {
		return err // Give up after 3 tries
	}

	// If connection is successful, start the reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		GroupID:  "pdvd-backend-worker",
		Topic:    topic,
		MaxBytes: 10e6,
	})

	go func() {
		defer reader.Close()
		service := &services.ReleaseServiceWrapper{DB: db}
		fetcher := &services.CIDFetcher{}

		log.Println("Kafka Event Processor started. Listening for release events...")

		for {
			select {
			case <-ctx.Done():
				return
			default:
				msg, err := reader.ReadMessage(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				_ = release.HandleReleaseSBOMCreatedWithService(ctx, msg.Value, fetcher, service)
			}
		}
	}()

	return nil
}
