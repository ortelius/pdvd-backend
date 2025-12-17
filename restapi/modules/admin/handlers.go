// Package admin implements the REST API handlers for admin operations.
// It provides endpoints for MTTR backfill processing and status monitoring.
package admin

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/lifecycle"
)

var backfillRunning = false
var backfillProgress = ""

// PostBackfillMTTR triggers the CVE lifecycle backfill process
func PostBackfillMTTR(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if backfillRunning {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"success": false,
				"message": "Backfill already in progress",
				"status":  backfillProgress,
			})
		}

		var req BackfillRequest
		if err := c.BodyParser(&req); err != nil {
			req.DaysBack = 90
		}

		if req.DaysBack <= 0 || req.DaysBack > 365 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "days_back must be between 1 and 365",
			})
		}

		go runBackfill(db, req.DaysBack)

		return c.JSON(fiber.Map{
			"success": true,
			"message": fmt.Sprintf("Backfill started for %d days of history", req.DaysBack),
			"status":  "processing",
		})
	}
}

// GetBackfillStatus returns the current status of any running backfill
func GetBackfillStatus() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.JSON(BackfillStatusResponse{
			Running: backfillRunning,
			Status:  backfillProgress,
		})
	}
}

func runBackfill(db database.DBConnection, daysBack int) {
	backfillRunning = true
	backfillProgress = fmt.Sprintf("Starting backfill for %d days...", daysBack)

	ctx := context.Background()
	cutoffDate := time.Now().AddDate(0, 0, -daysBack)

	log.Printf("Starting CVE lifecycle backfill for last %d days...", daysBack)

	// FIXED: Parse synced_at as DATE_TIMESTAMP and pass cutoffDate as milliseconds
	syncQuery := `
		FOR sync IN sync
			LET syncedAt = DATE_TIMESTAMP(sync.synced_at)
			FILTER syncedAt >= @cutoffDate
			SORT syncedAt ASC
			RETURN {
				endpoint_name: sync.endpoint_name,
				release_name: sync.release_name,
				release_version: sync.release_version,
				synced_at: syncedAt
			}
	`

	type SyncEvent struct {
		EndpointName   string    `json:"endpoint_name"`
		ReleaseName    string    `json:"release_name"`
		ReleaseVersion string    `json:"release_version"`
		SyncedAt       time.Time `json:"synced_at"`
	}

	cursor, err := db.Database.Query(ctx, syncQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cutoffDate": cutoffDate.Unix() * 1000, // FIXED: Pass as millisecond timestamp
		},
	})
	if err != nil {
		backfillProgress = fmt.Sprintf("Failed: %v", err)
		backfillRunning = false
		log.Printf("Backfill failed: %v", err)
		return
	}
	defer cursor.Close()

	var allSyncs []SyncEvent
	for cursor.HasMore() {
		var sync SyncEvent
		if _, err := cursor.ReadDocument(ctx, &sync); err == nil {
			allSyncs = append(allSyncs, sync)
		}
	}

	backfillProgress = fmt.Sprintf("Processing %d sync events...", len(allSyncs))
	log.Printf("Processing %d sync events", len(allSyncs))

	endpointSyncs := make(map[string][]SyncEvent)
	for _, sync := range allSyncs {
		endpointSyncs[sync.EndpointName] = append(endpointSyncs[sync.EndpointName], sync)
	}

	totalIntroductions := 0
	totalRemediations := 0
	processedEndpoints := 0

	for endpointName, syncs := range endpointSyncs {
		processedEndpoints++
		backfillProgress = fmt.Sprintf("Processing endpoint %d/%d: %s",
			processedEndpoints, len(endpointSyncs), endpointName)

		currentCVEs := make(map[string]lifecycle.CurrentCVEInfo)

		for _, sync := range syncs {
			newCVEs, err := lifecycle.GetCVEsForReleaseTracking(ctx, db, sync.ReleaseName, sync.ReleaseVersion)
			if err != nil {
				continue
			}

			newState := make(map[string]lifecycle.CurrentCVEInfo)
			for cveID, cveInfo := range newCVEs {
				key := fmt.Sprintf("%s:%s:%s", cveID, cveInfo.Package, sync.ReleaseName)
				newState[key] = lifecycle.CurrentCVEInfo{
					CVEKey: lifecycle.CVEKey{
						CveID:       cveID,
						Package:     cveInfo.Package,
						ReleaseName: sync.ReleaseName,
					},
					SeverityRating: cveInfo.SeverityRating,
					SeverityScore:  cveInfo.SeverityScore,
					Published:      cveInfo.Published,
					ReleaseVersion: sync.ReleaseVersion,
				}
			}

			for _, cveInfo := range newState {
				disclosedAfter := false
				if !cveInfo.Published.IsZero() {
					disclosedAfter = cveInfo.Published.After(sync.SyncedAt)
				}

				err := lifecycle.UpsertLifecycleRecord(ctx, db, endpointName, cveInfo, sync.SyncedAt, disclosedAfter)
				if err == nil {
					key := fmt.Sprintf("%s:%s:%s", cveInfo.CveID, cveInfo.Package, sync.ReleaseName)
					if _, existed := currentCVEs[key]; !existed {
						totalIntroductions++
					}
				}
			}

			for key, cveInfo := range currentCVEs {
				if _, stillExists := newState[key]; !stillExists {
					err := lifecycle.MarkCVERemediated(ctx, db, model.CVELifecycleEvent{
						Key:          "",
						EndpointName: endpointName,
						CveID:        cveInfo.CveID,
						Package:      cveInfo.Package,
						ReleaseName:  cveInfo.ReleaseName,
						IntroducedAt: time.Time{},
					}, sync.SyncedAt, sync.ReleaseVersion)

					if err == nil {
						totalRemediations++
					}
				}
			}

			currentCVEs = newState
		}
	}

	backfillProgress = fmt.Sprintf("Complete! Introductions: %d, Remediations: %d",
		totalIntroductions, totalRemediations)
	backfillRunning = false

	log.Printf("Backfill complete! Introductions: %d, Remediations: %d",
		totalIntroductions, totalRemediations)
}
