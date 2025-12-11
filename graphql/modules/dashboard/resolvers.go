// Package dashboard implements the resolvers for dashboard metrics.
package dashboard

import (
	"context"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/util"
)

func isVersionAffectedAny(version string, allAffected []models.Affected) bool {
	for _, affected := range allAffected {
		if util.IsVersionAffected(version, affected) {
			return true
		}
	}
	return false
}

// ResolveOverview handles fetching the high-level dashboard metrics
func ResolveOverview(_ database.DBConnection) (interface{}, error) {
	// TODO: Replace with actual database query calculating these metrics
	return map[string]interface{}{
		"total_releases":  142,
		"total_endpoints": 36,
		"total_cves":      328,
	}, nil
}

// ResolveSeverityDistribution fetches current breakdown of issues
func ResolveSeverityDistribution(_ database.DBConnection) (interface{}, error) {
	// TODO: Replace with actual database query for current severity snapshots
	return map[string]interface{}{
		"critical": 28,
		"high":     45,
		"medium":   32,
		"low":      15,
	}, nil
}

// ResolveTopRisks fetches the top risky assets based on type
func ResolveTopRisks(_ database.DBConnection, _ string, limit int) (interface{}, error) {
	// TODO: Replace with actual database query filtering by assetType
	var risks []map[string]interface{}
	risks = append(risks, map[string]interface{}{
		"name":           "payment-service-prod",
		"version":        "v2.1.0",
		"critical_count": 4,
		"high_count":     8,
		"total_vulns":    12,
	})
	if len(risks) > limit {
		return risks[:limit], nil
	}
	return risks, nil
}

// ResolveVulnerabilityTrend returns counts of vulns grouped by date using timestamp versioning
func ResolveVulnerabilityTrend(db database.DBConnection, days int) ([]map[string]interface{}, error) {
	ctx := context.Background()

	// ------------------------------------------------------------------------
	// STEP 1: Fetch All Sync History
	// We need the full history to reconstruct the state of endpoints at any given date.
	// Sorted by synced_at ASC to allow for chronological replay.
	// ------------------------------------------------------------------------
	syncQuery := `
		FOR s IN sync
			SORT s.synced_at ASC
			RETURN {
				endpoint: s.endpoint_name,
				release_name: s.release_name,
				release_version: s.release_version,
				synced_at: s.synced_at
			}
	`

	type SyncRecord struct {
		Endpoint       string `json:"endpoint"`
		ReleaseName    string `json:"release_name"`
		ReleaseVersion string `json:"release_version"`
		SyncedAt       string `json:"synced_at"`
	}

	syncCursor, err := db.Database.Query(ctx, syncQuery, nil)
	if err != nil {
		return []map[string]interface{}{}, err
	}
	defer syncCursor.Close()

	var syncHistory []SyncRecord
	type ReleaseKey struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	uniqueReleases := make(map[ReleaseKey]bool)

	for syncCursor.HasMore() {
		var rec SyncRecord
		if _, err := syncCursor.ReadDocument(ctx, &rec); err == nil {
			syncHistory = append(syncHistory, rec)
			uniqueReleases[ReleaseKey{Name: rec.ReleaseName, Version: rec.ReleaseVersion}] = true
		}
	}

	// ------------------------------------------------------------------------
	// STEP 2: Batch Fetch Vulnerabilities for All Releases
	// Uses the robust AQL filter + Go-side validation pattern for consistency.
	// ------------------------------------------------------------------------
	var releasesToFetch []ReleaseKey
	for k := range uniqueReleases {
		releasesToFetch = append(releasesToFetch, k)
	}

	type VulnCounts struct {
		Critical int
		High     int
		Medium   int
		Low      int
		Total    int
	}

	// Map: "name:version" -> VulnCounts
	releaseVulnStats := make(map[string]VulnCounts)

	if len(releasesToFetch) > 0 {
		vulnQuery := `
			FOR target IN @targets
				LET releaseDoc = (
					FOR r IN release
						FILTER r.name == target.name AND r.version == target.version
						LIMIT 1
						RETURN r
				)[0]
				
				FILTER releaseDoc != null
				
				LET sbomData = (
					FOR s IN 1..1 OUTBOUND releaseDoc release2sbom
						LIMIT 1
						RETURN { id: s._id }
				)[0]
				
				FILTER sbomData != null
				
				LET vulns = (
					FOR sbomEdge IN sbom2purl
						FILTER sbomEdge._from == sbomData.id
						LET purl = DOCUMENT(sbomEdge._to)
						FILTER purl != null
						
						FOR cveEdge IN cve2purl
							FILTER cveEdge._to == purl._id
							
							// ORIGINAL ROBUST FILTER: Handles semantic version comparison in AQL
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
								cve_id: cve.id,
								severity_rating: cve.database_specific.severity_rating,
								package: purl.purl,
								affected_version: sbomEdge.version,
								all_affected: matchedAffected,
								needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
							}
				)
				
				RETURN {
					name: target.name,
					version: target.version,
					vulns: vulns
				}
		`

		vCursor, err := db.Database.Query(ctx, vulnQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"targets": releasesToFetch,
			},
		})
		if err != nil {
			return nil, err
		}
		defer vCursor.Close()

		type VulnRaw struct {
			CveID           string            `json:"cve_id"`
			SeverityRating  string            `json:"severity_rating"`
			AffectedVersion string            `json:"affected_version"`
			AllAffected     []models.Affected `json:"all_affected"`
			NeedsValidation bool              `json:"needs_validation"`
		}

		type ReleaseResult struct {
			Name    string    `json:"name"`
			Version string    `json:"version"`
			Vulns   []VulnRaw `json:"vulns"`
		}

		for vCursor.HasMore() {
			var res ReleaseResult
			_, err := vCursor.ReadDocument(ctx, &res)
			if err != nil {
				continue
			}

			// Validate and Count
			counts := VulnCounts{}
			seen := make(map[string]bool) // Deduplicate by CVE ID

			for _, v := range res.Vulns {
				// 1. Conditional Go-side Validation
				if v.NeedsValidation {
					if len(v.AllAffected) > 0 {
						if !isVersionAffectedAny(v.AffectedVersion, v.AllAffected) {
							continue
						}
					}
				}

				if seen[v.CveID] {
					continue
				}
				seen[v.CveID] = true

				counts.Total++
				switch v.SeverityRating {
				case "CRITICAL":
					counts.Critical++
				case "HIGH":
					counts.High++
				case "MEDIUM":
					counts.Medium++
				case "LOW":
					counts.Low++
				}
			}
			releaseVulnStats[res.Name+":"+res.Version] = counts
		}
	}

	// ------------------------------------------------------------------------
	// STEP 3: Build Trend by Replaying Sync History
	// Iterate through each day, determining active releases using timestamp logic.
	// ------------------------------------------------------------------------
	var trendData []map[string]interface{}

	now := time.Now()
	// Generate date range (from `days` ago to today)
	// We go from oldest to newest
	for i := days - 1; i >= 0; i-- {
		targetDate := now.AddDate(0, 0, -i)
		targetDateStr := targetDate.Format("2006-01-02")
		// End of day timestamp for comparison
		endOfDayStr := targetDateStr + "T23:59:59Z"

		// Calculate state at end of this day
		// Map: Endpoint -> Current ReleaseKey
		endpointState := make(map[string]ReleaseKey)

		// Replay syncs up to this timestamp
		// Since syncHistory is sorted by time, we can just process in order
		// For a real optimization, we could maintain an index, but iterating is safe for typical history sizes.
		for _, sync := range syncHistory {
			if sync.SyncedAt > endOfDayStr {
				break // Future sync relative to targetDate
			}
			// Update state: Latest sync (by time) becomes the active release
			endpointState[sync.Endpoint] = ReleaseKey{Name: sync.ReleaseName, Version: sync.ReleaseVersion}
		}

		// Aggregate Vulnerabilities for this day
		dayCounts := VulnCounts{}
		for _, releaseKey := range endpointState {
			stats := releaseVulnStats[releaseKey.Name+":"+releaseKey.Version]
			dayCounts.Critical += stats.Critical
			dayCounts.High += stats.High
			dayCounts.Medium += stats.Medium
			dayCounts.Low += stats.Low
			dayCounts.Total += stats.Total
		}

		trendData = append(trendData, map[string]interface{}{
			"date":     targetDateStr,
			"critical": dayCounts.Critical,
			"high":     dayCounts.High,
			"medium":   dayCounts.Medium,
			"low":      dayCounts.Low,
			"total":    dayCounts.Total,
		})
	}

	return trendData, nil
}

// ResolveDashboardGlobalStatus calculates aggregated vulnerability counts and deltas across all synced endpoints
func ResolveDashboardGlobalStatus(db database.DBConnection, limit int) (map[string]interface{}, error) {
	ctx := context.Background()

	// ========================================================================
	// STEP 1: Inventory Query
	// Fetch all endpoints and their service inventory (Current vs Previous)
	// independently sorted by their own timestamp history.
	// ========================================================================
	inventoryQuery := `
		FOR endpoint IN endpoint
			LIMIT @limit
			LET services = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					COLLECT releaseName = sync.release_name INTO groups = sync
					
					// Sort all syncs for this specific service/endpoint combo by time
					LET sortedSyncs = (
						FOR s IN groups
							SORT s.synced_at DESC
							RETURN { 
								version: s.release_version, 
								synced_at: s.synced_at 
							}
					)
					
					// Current is the latest for this endpoint
					LET current = sortedSyncs[0]
					
					// Previous is the one immediately preceding it for this endpoint
					LET previous = LENGTH(sortedSyncs) > 1 ? sortedSyncs[1] : null
					
					RETURN {
						name: releaseName,
						current: current,
						previous: previous
					}
			)
			
			FILTER LENGTH(services) > 0
			
			RETURN {
				endpoint_name: endpoint.name,
				services: services
			}
	`

	cursor, err := db.Database.Query(ctx, inventoryQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"limit": limit,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	// Structures to hold the inventory
	type ServiceState struct {
		Version  string `json:"version"`
		SyncedAt string `json:"synced_at"`
	}
	type ServiceInventory struct {
		Name     string        `json:"name"`
		Current  ServiceState  `json:"current"`
		Previous *ServiceState `json:"previous"`
	}
	type EndpointInventory struct {
		EndpointName string             `json:"endpoint_name"`
		Services     []ServiceInventory `json:"services"`
	}

	var inventoryList []EndpointInventory

	// Track unique releases globally to batch-fetch vulnerabilities efficiently
	type ReleaseKey struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	uniqueReleases := make(map[ReleaseKey]bool)
	var releasesToFetch []ReleaseKey

	for cursor.HasMore() {
		var ep EndpointInventory
		_, err := cursor.ReadDocument(ctx, &ep)
		if err != nil {
			continue
		}
		inventoryList = append(inventoryList, ep)

		for _, svc := range ep.Services {
			// Current Version
			currKey := ReleaseKey{Name: svc.Name, Version: svc.Current.Version}
			if !uniqueReleases[currKey] {
				uniqueReleases[currKey] = true
				releasesToFetch = append(releasesToFetch, currKey)
			}
			// Previous Version (for Delta)
			if svc.Previous != nil {
				prevKey := ReleaseKey{Name: svc.Name, Version: svc.Previous.Version}
				if !uniqueReleases[prevKey] {
					uniqueReleases[prevKey] = true
					releasesToFetch = append(releasesToFetch, prevKey)
				}
			}
		}
	}

	// ========================================================================
	// STEP 2: Vulnerability Batch Query
	// Fetch potential vulnerabilities for ALL involved releases
	// ========================================================================

	// Map: "name:version" -> []VulnData
	releaseVulnMap := make(map[string][]map[string]interface{})

	if len(releasesToFetch) > 0 {
		vulnQuery := `
			FOR target IN @targets
				LET releaseDoc = (
					FOR r IN release
						FILTER r.name == target.name AND r.version == target.version
						LIMIT 1
						RETURN r
				)[0]
				
				FILTER releaseDoc != null
				
				LET sbomData = (
					FOR s IN 1..1 OUTBOUND releaseDoc release2sbom
						LIMIT 1
						RETURN { id: s._id }
				)[0]
				
				FILTER sbomData != null
				
				LET vulns = (
					FOR sbomEdge IN sbom2purl
						FILTER sbomEdge._from == sbomData.id
						LET purl = DOCUMENT(sbomEdge._to)
						FILTER purl != null
						
						FOR cveEdge IN cve2purl
							FILTER cveEdge._to == purl._id
							
							// ROBUST AQL FILTER
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
								cve_id: cve.id,
								severity_rating: cve.database_specific.severity_rating,
								affected_version: sbomEdge.version,
								all_affected: matchedAffected,
								needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
							}
				)
				
				RETURN {
					name: target.name,
					version: target.version,
					vulns: vulns
				}
		`

		vCursor, err := db.Database.Query(ctx, vulnQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"targets": releasesToFetch,
			},
		})
		if err != nil {
			return nil, err
		}
		defer vCursor.Close()

		type VulnRaw struct {
			CveID           string            `json:"cve_id"`
			SeverityRating  string            `json:"severity_rating"`
			AffectedVersion string            `json:"affected_version"`
			AllAffected     []models.Affected `json:"all_affected"`
			NeedsValidation bool              `json:"needs_validation"`
		}

		type ReleaseVulnResult struct {
			Name    string    `json:"name"`
			Version string    `json:"version"`
			Vulns   []VulnRaw `json:"vulns"`
		}

		for vCursor.HasMore() {
			var res ReleaseVulnResult
			_, err := vCursor.ReadDocument(ctx, &res)
			if err != nil {
				continue
			}

			var validVulns []map[string]interface{}
			seen := make(map[string]bool)

			for _, v := range res.Vulns {
				if v.NeedsValidation {
					if len(v.AllAffected) > 0 {
						if !isVersionAffectedAny(v.AffectedVersion, v.AllAffected) {
							continue
						}
					}
				}

				if seen[v.CveID] {
					continue
				}
				seen[v.CveID] = true

				validVulns = append(validVulns, map[string]interface{}{
					"cve_id":          v.CveID,
					"severity_rating": v.SeverityRating,
				})
			}
			releaseVulnMap[res.Name+":"+res.Version] = validVulns
		}
	}

	// ========================================================================
	// STEP 3: Aggregation
	// ========================================================================

	aggCritical := struct{ count, delta int }{}
	aggHigh := struct{ count, delta int }{}
	aggMedium := struct{ count, delta int }{}
	aggLow := struct{ count, delta int }{}
	totalCount := 0
	totalDelta := 0

	getReleaseCounts := func(name, version string) map[string]int {
		counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
		key := name + ":" + version
		vulns := releaseVulnMap[key]
		for _, v := range vulns {
			rating := v["severity_rating"].(string)
			counts["total"]++
			switch rating {
			case "CRITICAL":
				counts["critical"]++
			case "HIGH":
				counts["high"]++
			case "MEDIUM":
				counts["medium"]++
			case "LOW":
				counts["low"]++
			}
		}
		return counts
	}

	for _, ep := range inventoryList {
		// Calculate Stale Cutoff specific to THIS endpoint's latest sync time
		var latestSyncTime time.Time
		hasTime := false

		for _, svc := range ep.Services {
			if svc.Current.SyncedAt == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, svc.Current.SyncedAt)
			if err != nil {
				continue
			}
			if !hasTime || t.After(latestSyncTime) {
				latestSyncTime = t
				hasTime = true
			}
		}

		staleCutoff := latestSyncTime.Add(-2 * time.Hour) // Tolerance relative to this endpoint

		for _, svc := range ep.Services {
			// Current
			currCounts := getReleaseCounts(svc.Name, svc.Current.Version)

			aggCritical.count += currCounts["critical"]
			aggHigh.count += currCounts["high"]
			aggMedium.count += currCounts["medium"]
			aggLow.count += currCounts["low"]
			totalCount += currCounts["total"]

			// Delta Logic (Check Stale relative to THIS endpoint)
			isStale := false
			if hasTime && svc.Current.SyncedAt != "" {
				t, err := time.Parse(time.RFC3339, svc.Current.SyncedAt)
				if err == nil && t.Before(staleCutoff) {
					isStale = true
				}
			}

			if !isStale {
				prevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
				if svc.Previous != nil {
					prevCounts = getReleaseCounts(svc.Name, svc.Previous.Version)
				}

				aggCritical.delta += (currCounts["critical"] - prevCounts["critical"])
				aggHigh.delta += (currCounts["high"] - prevCounts["high"])
				aggMedium.delta += (currCounts["medium"] - prevCounts["medium"])
				aggLow.delta += (currCounts["low"] - prevCounts["low"])
				totalDelta += (currCounts["total"] - prevCounts["total"])
			}
		}
	}

	return map[string]interface{}{
		"critical":    map[string]int{"count": aggCritical.count, "delta": aggCritical.delta},
		"high":        map[string]int{"count": aggHigh.count, "delta": aggHigh.delta},
		"medium":      map[string]int{"count": aggMedium.count, "delta": aggMedium.delta},
		"low":         map[string]int{"count": aggLow.count, "delta": aggLow.delta},
		"total_count": totalCount,
		"total_delta": totalDelta,
	}, nil
}
