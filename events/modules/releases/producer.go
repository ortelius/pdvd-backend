// Package release handles Kafka event production for release SBOM creation events.
package release

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/segmentio/kafka-go"
)

// ReleaseProducer handles sending SBOM creation events to Kafka
type ReleaseProducer struct {
	Writer *kafka.Writer
}

// NewReleaseProducer initializes a new Kafka writer for release events
func NewReleaseProducer(brokers []string, topic string) *ReleaseProducer {
	return &ReleaseProducer{
		Writer: &kafka.Writer{
			Addr:     kafka.TCP(brokers...),
			Topic:    topic,
			Balancer: &kafka.LeastBytes{},
		},
	}
}

// PublishReleaseSBOMCreated sends the event to the Kafka topic
func (p *ReleaseProducer) PublishReleaseSBOMCreated(ctx context.Context, release model.ProjectRelease, cid string) error {

	// Construct the Event Contract
	event := ReleaseSBOMCreatedEvent{
		EventType:     "release.sbom.created",
		EventID:       uuid.New().String(),
		EventTime:     time.Now().UTC(),
		SchemaVersion: "v1",
		Release:       release,
		SBOMRef: SBOMReference{
			CID:         cid,
			StorageType: "ipfs", // Default storage type for the system
			UploadedAt:  time.Now().UTC(),
		},
	}

	// Marshal to JSON
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Write to Kafka
	return p.Writer.WriteMessages(ctx, kafka.Message{
		Key:   []byte(release.Name),
		Value: payload,
	})
}

// Close cleans up the Kafka writer
func (p *ReleaseProducer) Close() error {
	return p.Writer.Close()
}
