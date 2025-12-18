// Package sync handles the synchronization of release and CVE data.
// It processes SBOMs and updates CVE lifecycle tracking.
package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/lifecycle"
)

// ProcessSync handles a sync event and updates lifecycle tracking
// CRITICAL FIX: Now properly creates lifecycle records for EVERY version
// CRITICAL FIX: Compares with previous version to mark remediations
func ProcessSync(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	releaseVersion string,
	sbomCVEs []lifecycle.CVEInfo,  // CVEs extracted from this version's SBOM
	syncedAt time.Time,
) error {
	
	fmt.Printf("Processing sync: %s/%s version %s\n",
		endpointName, releaseName, releaseVersion)
	
	// Step 1: Find previous version (if any)
	previousVersion, err := lifecycle.GetPreviousVersion(
		ctx, db,
		releaseName, endpointName,
		syncedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to get previous version: %w", err)
	}
	
	isFirstDeployment := previousVersion == ""
	if isFirstDeployment {
		fmt.Printf("  First deployment of %s - creating lifecycle records\n", releaseName)
	} else {
		fmt.Printf("  Upgrading from %s to %s\n", previousVersion, releaseVersion)
	}
	
	// Step 2: Create lifecycle records for all CVEs in this version
	// Build a map of current CVEs for comparison
	currentCVEMap := make(map[string]lifecycle.CVEInfo)
	
	for _, cve := range sbomCVEs {
		key := fmt.Sprintf("%s:%s", cve.CVEID, cve.Package)
		currentCVEMap[key] = cve
		
		// Determine if this CVE was disclosed after deployment
		disclosedAfter := cve.Published.After(syncedAt)
		
		// CRITICAL: Pass the correct version and sync timestamp
		err := lifecycle.UpsertLifecycleRecord(
			ctx, db,
			endpointName,
			releaseName,
			releaseVersion,  // FIXED: Use actual version, not cached
			cve,
			syncedAt,        // FIXED: Use actual sync time, not time.Now()
			disclosedAfter,
		)
		
		if err != nil {
			return fmt.Errorf("failed to create lifecycle record for %s: %w", cve.CVEID, err)
		}
	}
	
	fmt.Printf("  Created/updated %d lifecycle records for version %s\n",
		len(sbomCVEs), releaseVersion)
	
	// Step 3: If not first deployment, compare with previous version
	// and mark remediations
	if !isFirstDeployment {
		err = lifecycle.CompareAndMarkRemediations(
			ctx, db,
			endpointName, releaseName,
			previousVersion, releaseVersion,
			currentCVEMap,
			syncedAt,
		)
		
		if err != nil {
			return fmt.Errorf("failed to compare versions: %w", err)
		}
	}
	
	return nil
}

// Example usage in your main sync handler:
/*
func HandleSyncEvent(ctx context.Context, db database.DBConnection, event SyncEvent) error {
	// 1. Extract SBOM and parse CVEs
	sbom, err := extractSBOM(event.ReleaseImage)
	if err != nil {
		return err
	}
	
	cves := parseCVEsFromSBOM(sbom)
	
	// 2. Create sync record
	syncRecord := map[string]interface{}{
		"release_name":    event.ReleaseName,
		"release_version": event.ReleaseVersion,
		"endpoint_name":   event.EndpointName,
		"synced_at":       event.SyncedAt,
		"objtype":         "Sync",
	}
	
	_, err = db.Collection("sync").CreateDocument(ctx, syncRecord)
	if err != nil {
		return err
	}
	
	// 3. Process lifecycle tracking (THIS IS THE CRITICAL STEP!)
	err = ProcessSync(
		ctx, db,
		event.EndpointName,
		event.ReleaseName,
		event.ReleaseVersion,
		cves,
		event.SyncedAt,
	)
	
	if err != nil {
		log.Printf("Warning: Failed to update CVE lifecycle tracking: %v", err)
		// Don't fail the sync, just log the error
	}
	
	return nil
}
*/
