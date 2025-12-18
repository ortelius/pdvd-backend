// Package lifecycle provides CVE lifecycle event tracking and management.
// It handles creation, updates, and remediation tracking for CVE lifecycle events.
package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/pdvd-backend/v12/database"
)

// CVEInfo contains the CVE data extracted from SBOM
type CVEInfo struct {
	CVEID         string
	Package       string
	SeverityScore float64
	SeverityRating string
	Published     time.Time
}

// UpsertLifecycleRecord creates or updates a CVE lifecycle record.
// FIXED: Now correctly uses sync timestamp and version from the sync event.
func UpsertLifecycleRecord(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	releaseVersion string,  // CRITICAL: Now passed in correctly
	cveInfo CVEInfo,
	syncedAt time.Time,      // CRITICAL: Use actual sync timestamp
	disclosedAfter bool,
) error {
	
	// Check if record already exists for this exact combination
	checkQuery := `
		FOR r IN cve_lifecycle
			FILTER r.cve_id == @cveId
			AND r.package == @package
			AND r.release_name == @releaseName
			AND r.endpoint_name == @endpointName
			AND r.introduced_version == @version
			LIMIT 1
			RETURN r
	`
	
	cursor, err := db.Database.Query(ctx, checkQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveId":       cveInfo.CVEID,
			"package":     cveInfo.Package,
			"releaseName": releaseName,
			"endpointName": endpointName,
			"version":      releaseVersion,
		},
	})
	
	if err != nil {
		return fmt.Errorf("failed to check existing record: %w", err)
	}
	defer cursor.Close()
	
	// If record exists, just update the timestamp (re-sync of same version)
	if cursor.HasMore() {
		var existing map[string]interface{}
		_, err := cursor.ReadDocument(ctx, &existing)
		if err != nil {
			return fmt.Errorf("failed to read existing record: %w", err)
		}
		
		// Just update the updated_at timestamp
		updateQuery := `
			UPDATE @key WITH {
				updated_at: @now
			} IN cve_lifecycle
		`
		
		_, err = db.Database.Query(ctx, updateQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"key": existing["_key"],
				"now": time.Now().UTC(),
			},
		})
		
		return err
	}
	
	// Record doesn't exist - create new one
	// CRITICAL FIX: Use syncedAt (actual sync time), not time.Now()
	// CRITICAL FIX: Use releaseVersion passed in, not some cached value
	record := map[string]interface{}{
		"cve_id":                     cveInfo.CVEID,
		"endpoint_name":              endpointName,
		"release_name":               releaseName,
		"package":                    cveInfo.Package,
		"severity_rating":            cveInfo.SeverityRating,
		"severity_score":             cveInfo.SeverityScore,
		"introduced_at":              syncedAt,  // FIXED: Use actual sync timestamp
		"introduced_version":         releaseVersion,  // FIXED: Use correct version
		"remediated_at":              nil,
		"remediated_version":         nil,
		"days_to_remediate":          nil,
		"is_remediated":              false,
		"disclosed_after_deployment": disclosedAfter,
		"published":                  cveInfo.Published,
		"objtype":                    "CVELifecycleEvent",
		"created_at":                 time.Now().UTC(),
		"updated_at":                 time.Now().UTC(),
	}
	
	_, err = db.Collection("cve_lifecycle").CreateDocument(ctx, record)
	if err != nil {
		return fmt.Errorf("failed to create lifecycle record: %w", err)
	}
	
	return nil
}

// MarkCVERemediated marks a CVE as remediated when it disappears in a new version
// FIXED: Now correctly tracks version transitions
func MarkCVERemediated(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	previousVersion string,  // ADDED: Track which version had the CVE
	currentVersion string,   // ADDED: Track which version fixed it
	cveID string,
	packagePURL string,
	remediatedAt time.Time,
) error {
	
	// Find the lifecycle record for the previous version
	query := `
		FOR r IN cve_lifecycle
			FILTER r.cve_id == @cveId
			AND r.package == @package
			AND r.release_name == @releaseName
			AND r.endpoint_name == @endpointName
			AND r.introduced_version == @previousVersion
			AND r.is_remediated == false
			LIMIT 1
			
			LET daysDiff = DATE_DIFF(
				DATE_TIMESTAMP(r.introduced_at),
				@remediatedAtTs,
				"d"
			)
			
			UPDATE r WITH {
				is_remediated: true,
				remediated_at: @remediatedAt,
				remediated_version: @currentVersion,
				days_to_remediate: daysDiff,
				updated_at: @now
			} IN cve_lifecycle
			
			RETURN NEW
	`
	
	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveId":           cveID,
			"package":         packagePURL,
			"releaseName":     releaseName,
			"endpointName":    endpointName,
			"previousVersion": previousVersion,
			"currentVersion":  currentVersion,
			"remediatedAt":    remediatedAt,
			"remediatedAtTs":  remediatedAt.Unix() * 1000,
			"now":             time.Now().UTC(),
		},
	})
	
	return err
}

// CompareAndMarkRemediations compares CVEs between versions and marks remediations
// CRITICAL: This function MUST be called after every sync to track fixes
func CompareAndMarkRemediations(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	previousVersion string,
	currentVersion string,
	currentCVEs map[string]CVEInfo,  // CVEs in current version (key: "cve_id:package")
	syncedAt time.Time,
) error {
	
	// Get all CVEs from the previous version
	query := `
		FOR r IN cve_lifecycle
			FILTER r.release_name == @releaseName
			AND r.endpoint_name == @endpointName
			AND r.introduced_version == @previousVersion
			AND r.is_remediated == false
			RETURN {
				cve_id: r.cve_id,
				package: r.package,
				key: CONCAT(r.cve_id, ":", r.package)
			}
	`
	
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"releaseName":     releaseName,
			"endpointName":    endpointName,
			"previousVersion": previousVersion,
		},
	})
	
	if err != nil {
		return fmt.Errorf("failed to query previous version CVEs: %w", err)
	}
	defer cursor.Close()
	
	type PreviousCVE struct {
		CVEID   string `json:"cve_id"`
		Package string `json:"package"`
		Key     string `json:"key"`
	}
	
	var previousCVEs []PreviousCVE
	for cursor.HasMore() {
		var cve PreviousCVE
		if _, err := cursor.ReadDocument(ctx, &cve); err == nil {
			previousCVEs = append(previousCVEs, cve)
		}
	}
	
	// Find CVEs that disappeared (were remediated)
	remediatedCount := 0
	for _, prevCVE := range previousCVEs {
		// If this CVE is NOT in the current version, it was fixed!
		if _, exists := currentCVEs[prevCVE.Key]; !exists {
			err := MarkCVERemediated(
				ctx, db,
				endpointName, releaseName,
				previousVersion, currentVersion,
				prevCVE.CVEID, prevCVE.Package,
				syncedAt,
			)
			if err != nil {
				return fmt.Errorf("failed to mark CVE as remediated: %w", err)
			}
			remediatedCount++
		}
	}
	
	fmt.Printf("Marked %d CVEs as remediated in transition %s -> %s\n",
		remediatedCount, previousVersion, currentVersion)
	
	return nil
}

// GetPreviousVersion finds the most recent version before the current one
func GetPreviousVersion(
	ctx context.Context,
	db database.DBConnection,
	releaseName string,
	endpointName string,
	currentSyncTime time.Time,
) (string, error) {
	
	query := `
		FOR s IN sync
			FILTER s.release_name == @releaseName
			AND s.endpoint_name == @endpointName
			AND DATE_TIMESTAMP(s.synced_at) < @currentTime
			SORT s.synced_at DESC
			LIMIT 1
			RETURN s.release_version
	`
	
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"releaseName":  releaseName,
			"endpointName": endpointName,
			"currentTime":  currentSyncTime.Unix() * 1000,
		},
	})
	
	if err != nil {
		return "", err
	}
	defer cursor.Close()
	
	if cursor.HasMore() {
		var version string
		_, err := cursor.ReadDocument(ctx, &version)
		return version, err
	}
	
	return "", nil  // No previous version (first deployment)
}
