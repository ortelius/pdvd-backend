// Package lifecycle provides CVE lifecycle event tracking and management.
// It handles creation, updates, and remediation tracking for CVE lifecycle events.
//
// This package is used by:
// - Sync handlers (when new versions are deployed)
// - OSV loader (when new CVEs are discovered)
// - Admin tools (backfill, manual corrections)
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/util"
)

// Note: CVEInfo, CVEKey, and CurrentCVEInfo types are defined in types.go

// ----------------------------------------------------------------------------
// Core Lifecycle Record Management
// ----------------------------------------------------------------------------

// CreateOrUpdateLifecycleRecord creates a new lifecycle record or updates existing one.
// This is the main entry point for lifecycle tracking.
//
// CRITICAL: This function checks for existing records by VERSION to enable:
// - Multiple lifecycle records per CVE (one per version)
// - Version-to-version remediation tracking
// - Proper timestamp handling
//
// Parameters:
//   - introducedAt: The actual deployment/sync timestamp (NOT time.Now()!)
//   - releaseVersion: The specific version where this CVE appears
//   - disclosedAfter: Whether CVE was published after deployment
func CreateOrUpdateLifecycleRecord(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	releaseVersion string,
	cveInfo CVEInfo,
	introducedAt time.Time,
	disclosedAfter bool,
) error {
	
	// Step 1: Check if record already exists for this EXACT combination
	// This prevents duplicates when the same version is re-synced
	checkQuery := `
		FOR rec IN cve_lifecycle
			FILTER rec.cve_id == @cve_id
			AND rec.package == @package
			AND rec.release_name == @release_name
			AND rec.endpoint_name == @endpoint_name
			AND rec.introduced_version == @version
			LIMIT 1
			RETURN rec
	`
	
	cursor, err := db.Database.Query(ctx, checkQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cve_id":        cveInfo.CVEID,
			"package":       cveInfo.Package,
			"release_name":  releaseName,
			"endpoint_name": endpointName,
			"version":       releaseVersion,
		},
	})
	
	if err != nil {
		return fmt.Errorf("failed to check existing lifecycle record: %w", err)
	}
	defer cursor.Close()
	
	// If record exists for this version, just update timestamp
	if cursor.HasMore() {
		var existing map[string]interface{}
		_, err := cursor.ReadDocument(ctx, &existing)
		if err != nil {
			return fmt.Errorf("failed to read existing record: %w", err)
		}
		
		// Update: Touch timestamp and maintain "once post-deploy, always post-deploy" logic
		updateQuery := `
			UPDATE @key WITH {
				updated_at: DATE_NOW(),
				disclosed_after_deployment: OLD.disclosed_after_deployment || @disclosed_after
			} IN cve_lifecycle
		`
		
		_, err = db.Database.Query(ctx, updateQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"key":             existing["_key"],
				"disclosed_after": disclosedAfter,
			},
		})
		
		return err
	}
	
	// Step 2: Record doesn't exist - create new one
	// CRITICAL: Use introducedAt (actual deployment time), not time.Now()
	// CRITICAL: Use releaseVersion from parameter, not cached value
	record := map[string]interface{}{
		"cve_id":                     cveInfo.CVEID,
		"endpoint_name":              endpointName,
		"release_name":               releaseName,
		"package":                    cveInfo.Package,
		"severity_rating":            cveInfo.SeverityRating,
		"severity_score":             cveInfo.SeverityScore,
		"introduced_at":              introducedAt,  // ✅ Actual sync/deployment time
		"introduced_version":         releaseVersion,  // ✅ Specific version
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
	
	_, err = db.Collections["cve_lifecycle"].CreateDocument(ctx, record)
	if err != nil {
		return fmt.Errorf("failed to create lifecycle record: %w", err)
	}
	
	return nil
}

// ----------------------------------------------------------------------------
// Remediation Tracking
// ----------------------------------------------------------------------------

// MarkCVERemediated marks a CVE as remediated when it disappears in a new version.
// This tracks the version transition and calculates days to remediate.
func MarkCVERemediated(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	previousVersion string,
	currentVersion string,
	cveID string,
	packagePURL string,
	remediatedAt time.Time,
) error {
	
	// Find the lifecycle record for the previous version
	query := `
		FOR r IN cve_lifecycle
			FILTER r.cve_id == @cve_id
			AND r.package == @package
			AND r.release_name == @release_name
			AND r.endpoint_name == @endpoint_name
			AND r.introduced_version == @previous_version
			AND r.is_remediated == false
			LIMIT 1
			
			LET daysDiff = DATE_DIFF(
				DATE_TIMESTAMP(r.introduced_at),
				@remediated_at_ts,
				"d"
			)
			
			UPDATE r WITH {
				is_remediated: true,
				remediated_at: @remediated_at,
				remediated_version: @current_version,
				days_to_remediate: daysDiff,
				updated_at: DATE_NOW()
			} IN cve_lifecycle
			
			RETURN NEW
	`
	
	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cve_id":           cveID,
			"package":          packagePURL,
			"release_name":     releaseName,
			"endpoint_name":    endpointName,
			"previous_version": previousVersion,
			"current_version":  currentVersion,
			"remediated_at":    remediatedAt,
			"remediated_at_ts": remediatedAt.Unix() * 1000,
		},
	})
	
	if err != nil {
		return fmt.Errorf("failed to mark CVE as remediated: %w", err)
	}
	
	return nil
}

// CompareAndMarkRemediations compares CVEs between versions and marks remediations.
// This is called during sync to detect which CVEs were fixed in the version upgrade.
func CompareAndMarkRemediations(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	previousVersion string,
	currentVersion string,
	currentCVEs map[string]CVEInfo,  // Key format: "cve_id:package"
	remediatedAt time.Time,
) (int, error) {
	
	// Get all CVEs from the previous version that are still open
	query := `
		FOR r IN cve_lifecycle
			FILTER r.release_name == @release_name
			AND r.endpoint_name == @endpoint_name
			AND r.introduced_version == @previous_version
			AND r.is_remediated == false
			RETURN {
				cve_id: r.cve_id,
				package: r.package,
				key: CONCAT(r.cve_id, ":", r.package)
			}
	`
	
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"release_name":     releaseName,
			"endpoint_name":    endpointName,
			"previous_version": previousVersion,
		},
	})
	
	if err != nil {
		return 0, fmt.Errorf("failed to query previous version CVEs: %w", err)
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
				remediatedAt,
			)
			if err != nil {
				return remediatedCount, fmt.Errorf("failed to mark CVE %s as remediated: %w", prevCVE.CVEID, err)
			}
			remediatedCount++
		}
	}
	
	return remediatedCount, nil
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// GetPreviousVersion finds the most recent version before the current one.
// Returns empty string if this is the first deployment.
func GetPreviousVersion(
	ctx context.Context,
	db database.DBConnection,
	releaseName string,
	endpointName string,
	currentSyncTime time.Time,
) (string, error) {
	
	query := `
		FOR s IN sync
			FILTER s.release_name == @release_name
			AND s.endpoint_name == @endpoint_name
			AND DATE_TIMESTAMP(s.synced_at) < @current_time
			SORT s.synced_at DESC
			LIMIT 1
			RETURN s.release_version
	`
	
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"release_name":  releaseName,
			"endpoint_name": endpointName,
			"current_time":  currentSyncTime.Unix() * 1000,
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

// GetSyncTimestamp retrieves the sync timestamp for a specific release version.
// This is used when creating lifecycle records from historical data.
func GetSyncTimestamp(
	ctx context.Context,
	db database.DBConnection,
	releaseName string,
	releaseVersion string,
	endpointName string,
) (time.Time, error) {
	
	query := `
		FOR s IN sync
			FILTER s.release_name == @release_name
			AND s.release_version == @release_version
			AND s.endpoint_name == @endpoint_name
			SORT s.synced_at DESC
			LIMIT 1
			RETURN s.synced_at
	`
	
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"release_name":    releaseName,
			"release_version": releaseVersion,
			"endpoint_name":   endpointName,
		},
	})
	
	if err != nil {
		return time.Time{}, err
	}
	defer cursor.Close()
	
	if cursor.HasMore() {
		var timestamp time.Time
		_, err := cursor.ReadDocument(ctx, &timestamp)
		return timestamp, err
	}
	
	return time.Time{}, fmt.Errorf("no sync record found for %s version %s", releaseName, releaseVersion)
}

// BuildCVEMap creates a map of CVEs keyed by "cve_id:package" for efficient lookup.
// This is used when comparing versions to detect remediations.
func BuildCVEMap(cves []CVEInfo) map[string]CVEInfo {
	result := make(map[string]CVEInfo)
	for _, cve := range cves {
		key := fmt.Sprintf("%s:%s", cve.CVEID, cve.Package)
		result[key] = cve
	}
	return result
}

// GetCVEsForReleaseTracking retrieves all CVEs affecting a specific release version.
// This is used by the backfill process and OSV loader to get current CVE state.
// Returns map[cveID]CVEInfo for efficient lookup.
func GetCVEsForReleaseTracking(
	ctx context.Context,
	db database.DBConnection,
	releaseName string,
	releaseVersion string,
) (map[string]CVEInfo, error) {
	
	// Query to get all CVEs for this release using release2cve edges
	query := `
		FOR release IN release
			FILTER release.name == @release_name
			AND release.version == @release_version
			LIMIT 1
			
			FOR cve, edge IN 1..1 OUTBOUND release release2cve
				RETURN {
					cve_id: cve.id,
					package: edge.package_purl,
					severity_rating: cve.database_specific.severity_rating,
					severity_score: cve.database_specific.cvss_base_score,
					published: cve.published
				}
	`
	
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"release_name":    releaseName,
			"release_version": releaseVersion,
		},
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to query CVEs for release: %w", err)
	}
	defer cursor.Close()
	
	type CVERaw struct {
		CveID          string  `json:"cve_id"`
		Package        string  `json:"package"`
		SeverityRating string  `json:"severity_rating"`
		SeverityScore  float64 `json:"severity_score"`
		Published      string  `json:"published"`
	}
	
	result := make(map[string]CVEInfo)
	
	for cursor.HasMore() {
		var raw CVERaw
		if _, err := cursor.ReadDocument(ctx, &raw); err != nil {
			continue
		}
		
		var publishedTime time.Time
		if raw.Published != "" {
			if t, err := time.Parse(time.RFC3339, raw.Published); err == nil {
				publishedTime = t
			}
		}
		
		result[raw.CveID] = CVEInfo{
			CVEID:          raw.CveID,
			Package:        raw.Package,
			SeverityRating: raw.SeverityRating,
			SeverityScore:  raw.SeverityScore,
			Published:      publishedTime,
		}
	}
	
	return result, nil
}

// CreateRelease2CVEEdges creates materialized edges from release to CVEs
// by matching packages in the SBOM with known CVE-to-package relationships.
// Uses IsVersionAffectedAny for validation like OSV loader.
func CreateRelease2CVEEdges(ctx context.Context, db database.DBConnection, releaseID string) error {
	fmt.Printf("[CreateRelease2CVEEdges] Starting for releaseID: %s\n", releaseID)
	
	// Query to get candidates that need validation
	query := `
		LET release = DOCUMENT(@release_id)
		
		LET sbomData = FIRST(
			FOR s IN 1..1 OUTBOUND release release2sbom
				LIMIT 1
				RETURN s
		)
		
		FILTER sbomData != null
		
		FOR sbomEdge IN sbom2purl
			FILTER sbomEdge._from == sbomData._id
			LET purl = DOCUMENT(sbomEdge._to)
			FILTER purl != null
			
			FOR cveEdge IN cve2purl
				FILTER cveEdge._to == purl._id
				
				FILTER (
					sbomEdge.version_major != null AND 
					cveEdge.introduced_major != null AND 
					(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
				) ? (
					(sbomEdge.version_major > cveEdge.introduced_major OR
					(sbomEdge.version_major == cveEdge.introduced_major AND 
					sbomEdge.version_minor > cveEdge.introduced_minor) OR
					(sbomEdge.version_major == cveEdge.introduced_major AND 
					sbomEdge.version_minor == cveEdge.introduced_minor AND 
					sbomEdge.version_patch >= cveEdge.introduced_patch))
					AND
					(cveEdge.fixed_major != null ? (
						sbomEdge.version_major < cveEdge.fixed_major OR
						(sbomEdge.version_major == cveEdge.fixed_major AND 
						sbomEdge.version_minor < cveEdge.fixed_minor) OR
						(sbomEdge.version_major == cveEdge.fixed_major AND 
						sbomEdge.version_minor == cveEdge.fixed_minor AND 
						sbomEdge.version_patch < cveEdge.fixed_patch)
					) : (
						sbomEdge.version_major < cveEdge.last_affected_major OR
						(sbomEdge.version_major == cveEdge.last_affected_major AND 
						sbomEdge.version_minor < cveEdge.last_affected_minor) OR
						(sbomEdge.version_major == cveEdge.last_affected_major AND 
						sbomEdge.version_minor == cveEdge.last_affected_minor AND 
						sbomEdge.version_patch <= cveEdge.last_affected_patch)
					))
				) : true
				
				LET cve = DOCUMENT(cveEdge._from)
				FILTER cve != null
				
				LET matchedAffected = (
					FOR affected IN cve.affected != null ? cve.affected : []
						LET cveBasePurl = affected.package.purl != null ? 
							affected.package.purl : 
							CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
						FILTER cveBasePurl == purl.purl
						RETURN affected
				)
				FILTER LENGTH(matchedAffected) > 0
				
				RETURN {
					cve_id: cve._id,
					package_purl: purl.purl,
					package_version: sbomEdge.version,
					all_affected: matchedAffected,
					needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
				}
	`
	
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"release_id": releaseID,
		},
	})
	if err != nil {
		fmt.Printf("[CreateRelease2CVEEdges] ERROR: Query failed: %v\n", err)
		return err
	}
	defer cursor.Close()
	
	fmt.Printf("[CreateRelease2CVEEdges] Query executed, checking for candidates...\n")
	
	type EdgeCandidate struct {
		CveID           string            `json:"cve_id"`
		PackagePurl     string            `json:"package_purl"`
		PackageVersion  string            `json:"package_version"`
		AllAffected     json.RawMessage   `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}
	
	seenEdges := make(map[string]bool)
	candidateCount := 0
	validatedCount := 0
	createdCount := 0
	skippedCount := 0
	
	for cursor.HasMore() {
		candidateCount++
		var cand EdgeCandidate
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			fmt.Printf("[CreateRelease2CVEEdges] ERROR: Failed to read candidate %d: %v\n", candidateCount, err)
			continue
		}
		
		fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: CVE=%s, Package=%s, Version=%s, NeedsValidation=%v\n",
			candidateCount, cand.CveID, cand.PackagePurl, cand.PackageVersion, cand.NeedsValidation)
		
		// Validate using IsVersionAffectedAny if needed
		if cand.NeedsValidation {
			// Parse AllAffected from JSON
			var affected []models.Affected
			if err := json.Unmarshal(cand.AllAffected, &affected); err != nil {
				fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: ERROR parsing affected: %v\n", candidateCount, err)
				skippedCount++
				continue
			}
			
			if !util.IsVersionAffectedAny(cand.PackageVersion, affected) {
				fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: SKIPPED - Version not affected\n", candidateCount)
				skippedCount++
				continue
			}
			fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: VALIDATED - Version is affected\n", candidateCount)
			validatedCount++
		}
		
		// Create unique key
		edgeKey := releaseID + ":" + cand.CveID + ":" + cand.PackagePurl
		if seenEdges[edgeKey] {
			fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: SKIPPED - Duplicate edge\n", candidateCount)
			skippedCount++
			continue
		}
		seenEdges[edgeKey] = true
		
		// Check if edge exists
		checkQuery := `
			FOR e IN release2cve
				FILTER e._from == @from AND e._to == @to AND e.package_purl == @purl
				LIMIT 1
				RETURN e
		`
		checkCursor, err := db.Database.Query(ctx, checkQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"from": releaseID,
				"to":   cand.CveID,
				"purl": cand.PackagePurl,
			},
		})
		if err != nil {
			fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: ERROR checking existing edge: %v\n", candidateCount, err)
			continue
		}
		
		edgeExists := checkCursor.HasMore()
		checkCursor.Close()
		
		if !edgeExists {
			edge := map[string]interface{}{
				"_from":           releaseID,
				"_to":             cand.CveID,
				"type":            "sbom_analysis",
				"package_purl":    cand.PackagePurl,
				"package_version": cand.PackageVersion,
				"created_at":      time.Now(),
			}
			
			_, err = db.Collections["release2cve"].CreateDocument(ctx, edge)
			if err != nil {
				fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: ERROR creating edge: %v\n", candidateCount, err)
				continue
			}
			fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: CREATED edge successfully\n", candidateCount)
			createdCount++
		} else {
			fmt.Printf("[CreateRelease2CVEEdges] Candidate %d: SKIPPED - Edge already exists\n", candidateCount)
			skippedCount++
		}
	}
	
	fmt.Printf("[CreateRelease2CVEEdges] Summary: Total=%d, Validated=%d, Created=%d, Skipped=%d\n",
		candidateCount, validatedCount, createdCount, skippedCount)
	
	return nil
}
