// Package endpoints implements the resolvers for endpoint data.
package endpoints

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/util"
)

// ResolveEndpointDetails - returns detailed endpoint information with vulnerabilities
// REFACTORED: Now uses release2cve materialized edges instead of complex AQL filtering
func ResolveEndpointDetails(db database.DBConnection, endpointName string) (map[string]interface{}, error) {
	ctx := context.Background()

	decodedName, err := url.QueryUnescape(endpointName)
	if err != nil {
		decodedName = endpointName
	}

	// ========================================================================
	// STEP 1: Inventory Query
	// Get endpoint details and list of services with their Current vs Previous versions
	// ========================================================================
	inventoryQuery := `
		FOR endpoint IN endpoint
			FILTER endpoint.name == @endpointName
			LIMIT 1
			
			LET services = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					COLLECT releaseName = sync.release_name INTO groups = sync
					
					// Sort all syncs for this service by time descending (Timestamp Versioning)
					LET sortedSyncs = (
						FOR s IN groups
							SORT s.synced_at DESC
							RETURN { 
								version: s.release_version, 
								synced_at: s.synced_at 
							}
					)
					
					// Current is the 1st (Latest)
					LET current = sortedSyncs[0]
					
					// Previous is the 2nd (if exists)
					LET previous = LENGTH(sortedSyncs) > 1 ? sortedSyncs[1] : null
					
					// Fetch Release Metadata for Current
					LET releaseDoc = (
						FOR r IN release
							FILTER r.name == releaseName AND r.version == current.version
							LIMIT 1
							RETURN r
					)[0]
					
					FILTER releaseDoc != null
					
					RETURN {
						name: releaseName,
						current: current,
						previous: previous,
						release_doc: {
							openssf_scorecard_score: releaseDoc.openssf_scorecard_score,
							project_type: releaseDoc.projecttype
						}
					}
			)
			
			RETURN {
				endpoint: endpoint,
				services: services
			}
	`

	type ServiceState struct {
		Version  string `json:"version"`
		SyncedAt string `json:"synced_at"`
	}

	type ServiceInventory struct {
		Name       string        `json:"name"`
		Current    ServiceState  `json:"current"`
		Previous   *ServiceState `json:"previous"`
		ReleaseDoc struct {
			ScorecardScore *float64 `json:"openssf_scorecard_score"`
			ProjectType    string   `json:"project_type"`
		} `json:"release_doc"`
	}

	type InventoryResult struct {
		Endpoint struct {
			Name         string `json:"name"`
			EndpointType string `json:"endpoint_type"`
			Environment  string `json:"environment"`
		} `json:"endpoint"`
		Services []ServiceInventory `json:"services"`
	}

	cursor, err := db.Database.Query(ctx, inventoryQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"endpointName": decodedName,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	if !cursor.HasMore() {
		return nil, nil // Endpoint not found
	}

	var inventory InventoryResult
	_, err = cursor.ReadDocument(ctx, &inventory)
	if err != nil {
		return nil, err
	}

	// ========================================================================
	// STEP 2: Prepare Batch List
	// Collect all unique (Name, Version) pairs we need to fetch vulns for
	// ========================================================================
	type ReleaseKey struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	uniqueReleases := make(map[string]bool)
	var releasesToFetch []ReleaseKey

	for _, svc := range inventory.Services {
		// Add Current
		currKey := svc.Name + ":" + svc.Current.Version
		if !uniqueReleases[currKey] {
			uniqueReleases[currKey] = true
			releasesToFetch = append(releasesToFetch, ReleaseKey{svc.Name, svc.Current.Version})
		}

		// Add Previous (if exists)
		if svc.Previous != nil {
			prevKey := svc.Name + ":" + svc.Previous.Version
			if !uniqueReleases[prevKey] {
				uniqueReleases[prevKey] = true
				releasesToFetch = append(releasesToFetch, ReleaseKey{svc.Name, svc.Previous.Version})
			}
		}
	}

	// ========================================================================
	// STEP 3: Vulnerability Batch Query
	// REFACTORED: Use release2cve materialized edges (pre-validated at write-time)
	// ========================================================================

	// Map to store results: "name:version" -> []VulnMatch
	releaseVulnMap := make(map[string][]map[string]interface{})

	if len(releasesToFetch) > 0 {
		// REFACTORED: Simple edge traversal instead of complex filtering
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
				
				// Get Dependency Count
				LET dependencyCount = (
					FILTER sbomData != null
					FOR edge IN sbom2purl
						FILTER edge._from == sbomData.id
						COLLECT fullPurl = edge.full_purl
						RETURN 1
				)
				
				// Get Vulnerabilities using release2cve materialized edges
				// Edges are pre-validated during ingestion - no filtering needed
				LET vulns = (
					FOR cve, edge IN 1..1 OUTBOUND releaseDoc release2cve
						RETURN {
							cve_id: cve.id,
							summary: cve.summary,
							severity_score: cve.database_specific.cvss_base_score,
							severity_rating: cve.database_specific.severity_rating,
							
							// Retrieved directly from materialized edge
							package: edge.package_purl,
							affected_version: edge.package_version,
							full_purl: edge.package_purl,
							
							// Still needed for fixed_in calculation
							all_affected: cve.affected
						}
				)
				
				RETURN {
					name: target.name,
					version: target.version,
					dependency_count: LENGTH(dependencyCount),
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
			CveID           string                   `json:"cve_id"`
			Summary         string                   `json:"summary"`
			SeverityScore   float64                  `json:"severity_score"`
			SeverityRating  string                   `json:"severity_rating"`
			Package         string                   `json:"package"`
			AffectedVersion string                   `json:"affected_version"`
			FullPurl        string                   `json:"full_purl"`
			AllAffected     []map[string]interface{} `json:"all_affected"`
		}

		type ReleaseResult struct {
			Name            string    `json:"name"`
			Version         string    `json:"version"`
			DependencyCount int       `json:"dependency_count"`
			Vulns           []VulnRaw `json:"vulns"`
		}

		for vCursor.HasMore() {
			var res ReleaseResult
			_, err := vCursor.ReadDocument(ctx, &res)
			if err != nil {
				continue
			}

			// NO VALIDATION NEEDED - edges are pre-validated during ingestion
			// Just perform local deduplication
			var validVulns []map[string]interface{}
			seen := make(map[string]bool)

			for _, v := range res.Vulns {
				// Local deduplication for this release
				key := v.CveID + ":" + v.Package
				if seen[key] {
					continue
				}
				seen[key] = true

				validVulns = append(validVulns, map[string]interface{}{
					"cve_id":           v.CveID,
					"summary":          v.Summary,
					"severity_score":   v.SeverityScore,
					"severity_rating":  v.SeverityRating,
					"package":          v.Package,
					"affected_version": v.AffectedVersion,
					"full_purl":        v.FullPurl,
					"fixed_in":         util.ExtractApplicableFixedVersion(v.AffectedVersion, convertToModelsAffected(v.AllAffected)),
					"dependency_count": res.DependencyCount,
				})
			}
			releaseVulnMap[res.Name+":"+res.Version] = validVulns
		}
	}

	// ========================================================================
	// STEP 4: Assembly and Delta Calculation
	// ========================================================================

	var finalReleases []map[string]interface{}

	// Aggregators for the Endpoint
	endpointCurrCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	endpointPrevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}

	for _, svc := range inventory.Services {
		// --- Current State ---
		currKey := svc.Name + ":" + svc.Current.Version
		currVulns := releaseVulnMap[currKey]

		currServiceCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		dependencyCount := 0

		if len(currVulns) > 0 {
			dependencyCount = currVulns[0]["dependency_count"].(int)
		}

		for _, v := range currVulns {
			rating := v["severity_rating"].(string)
			switch rating {
			case "CRITICAL":
				currServiceCounts["critical"]++
			case "HIGH":
				currServiceCounts["high"]++
			case "MEDIUM":
				currServiceCounts["medium"]++
			case "LOW":
				currServiceCounts["low"]++
			}
		}

		// --- Previous State ---
		prevServiceCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		if svc.Previous != nil {
			prevKey := svc.Name + ":" + svc.Previous.Version
			prevVulns := releaseVulnMap[prevKey]
			for _, v := range prevVulns {
				rating := v["severity_rating"].(string)
				switch rating {
				case "CRITICAL":
					prevServiceCounts["critical"]++
				case "HIGH":
					prevServiceCounts["high"]++
				case "MEDIUM":
					prevServiceCounts["medium"]++
				case "LOW":
					prevServiceCounts["low"]++
				}
			}
		}

		// --- Aggregation ---
		totalCurr := 0
		for k, v := range currServiceCounts {
			endpointCurrCounts[k] += v
			totalCurr += v
		}

		totalPrev := 0
		for k, v := range prevServiceCounts {
			endpointPrevCounts[k] += v
			totalPrev += v
		}

		svcDelta := totalCurr - totalPrev

		// Add to response list
		finalReleases = append(finalReleases, map[string]interface{}{
			"release_name":              svc.Name,
			"release_version":           svc.Current.Version,
			"openssf_scorecard_score":   svc.ReleaseDoc.ScorecardScore,
			"dependency_count":          dependencyCount,
			"last_sync":                 svc.Current.SyncedAt,
			"vulnerability_count":       totalCurr,
			"vulnerability_count_delta": svcDelta,
			"vulnerabilities":           currVulns,
		})
	}

	// Calculate Endpoint-wide Deltas
	deltaCritical := endpointCurrCounts["critical"] - endpointPrevCounts["critical"]
	deltaHigh := endpointCurrCounts["high"] - endpointPrevCounts["high"]
	deltaMedium := endpointCurrCounts["medium"] - endpointPrevCounts["medium"]
	deltaLow := endpointCurrCounts["low"] - endpointPrevCounts["low"]

	totalDelta := deltaCritical + deltaHigh + deltaMedium + deltaLow

	// Determine latest sync time across all services
	lastSync := ""
	for _, svc := range inventory.Services {
		if lastSync == "" || svc.Current.SyncedAt > lastSync {
			lastSync = svc.Current.SyncedAt
		}
	}

	return map[string]interface{}{
		"endpoint_name":             inventory.Endpoint.Name,
		"endpoint_url":              inventory.Endpoint.Name,
		"endpoint_type":             inventory.Endpoint.EndpointType,
		"environment":               inventory.Endpoint.Environment,
		"status":                    "active",
		"last_sync":                 lastSync,
		"total_vulnerabilities":     endpointCurrCounts,
		"vulnerability_count_delta": totalDelta,
		"releases":                  finalReleases,
	}, nil
}

// ResolveSyncedEndpoints fetches a list of endpoints that have been synced.
// REFACTORED: Now uses release2cve materialized edges instead of complex AQL filtering
// FIXED: Moved deduplication outside service loop to correctly count across all services
func ResolveSyncedEndpoints(db database.DBConnection, limit int, org string) ([]map[string]interface{}, error) {
	ctx := context.Background()

	// ========================================================================
	// STEP 1: Inventory Query
	// Get all endpoints and their service inventory sorted by timestamp
	// ========================================================================
	inventoryQuery := `
		FOR endpoint IN endpoint
			LIMIT @limit
			
			LET services = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					COLLECT releaseName = sync.release_name INTO groups = sync
					
					// Sort all syncs for this service by time descending (Timestamp Versioning)
					LET sortedSyncs = (
						FOR s IN groups
							SORT s.synced_at DESC
							RETURN { 
								version: s.release_version, 
								synced_at: s.synced_at 
							}
					)
					
					// Current is the 1st (Latest Deployed)
					LET current = sortedSyncs[0]

					// Previous is the 2nd (if exists) for Delta calculation
					LET previous = LENGTH(sortedSyncs) > 1 ? sortedSyncs[1] : null

					// Check Org if filter is present
					LET releaseDoc = (
						FOR r IN release
							FILTER r.name == releaseName AND r.version == current.version
							LIMIT 1
							RETURN r
					)[0]

					FILTER @org == "" OR releaseDoc.org == @org
					
					RETURN {
						name: releaseName,
						current: current,
						previous: previous
					}
			)
			
			// Only return endpoints that actually have services (matching the org filter)
			FILTER LENGTH(services) > 0
			
			// Calculate the last sync time across all services
			LET lastSync = MAX(services[*].current.synced_at)
			
			RETURN {
				endpoint_name: endpoint.name,
				endpoint_url: endpoint.name,
				endpoint_type: endpoint.endpoint_type,
				environment: endpoint.environment,
				status: "active",
				last_sync: lastSync,
				release_count: LENGTH(services),
				services: services
			}
	`

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
		EndpointURL  string             `json:"endpoint_url"`
		EndpointType string             `json:"endpoint_type"`
		Environment  string             `json:"environment"`
		Status       string             `json:"status"`
		LastSync     string             `json:"last_sync"`
		ReleaseCount int                `json:"release_count"`
		Services     []ServiceInventory `json:"services"`
	}

	cursor, err := db.Database.Query(ctx, inventoryQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"limit": limit,
			"org":   org,
		},
	})
	if err != nil {
		return []map[string]interface{}{}, nil
	}
	defer cursor.Close()

	var endpointsInv []EndpointInventory

	// ========================================================================
	// STEP 2: Prepare Batch List
	// Collect all unique (Name, Version) pairs we need to fetch vulns for
	// ========================================================================
	type ReleaseKey struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	uniqueReleases := make(map[string]bool)
	var releasesToFetch []ReleaseKey

	for cursor.HasMore() {
		var ep EndpointInventory
		_, err := cursor.ReadDocument(ctx, &ep)
		if err != nil {
			continue
		}
		endpointsInv = append(endpointsInv, ep)

		for _, svc := range ep.Services {
			// Current
			currKey := svc.Name + ":" + svc.Current.Version
			if !uniqueReleases[currKey] {
				uniqueReleases[currKey] = true
				releasesToFetch = append(releasesToFetch, ReleaseKey{svc.Name, svc.Current.Version})
			}
			// Previous (for Delta)
			if svc.Previous != nil {
				prevKey := svc.Name + ":" + svc.Previous.Version
				if !uniqueReleases[prevKey] {
					uniqueReleases[prevKey] = true
					releasesToFetch = append(releasesToFetch, ReleaseKey{svc.Name, svc.Previous.Version})
				}
			}
		}
	}

	if len(endpointsInv) == 0 {
		return []map[string]interface{}{}, nil
	}

	// ========================================================================
	// STEP 3: Vulnerability Batch Query
	// REFACTORED: Use release2cve materialized edges (pre-validated at write-time)
	// ========================================================================

	// Map: "name:version" -> []VulnData
	releaseVulnMap := make(map[string][]map[string]interface{})

	if len(releasesToFetch) > 0 {
		// REFACTORED: Simple edge traversal instead of complex filtering
		vulnQuery := `
			FOR target IN @targets
				LET releaseDoc = (
					FOR r IN release
						FILTER r.name == target.name AND r.version == target.version
						LIMIT 1
						RETURN r
				)[0]
				
				FILTER releaseDoc != null
				
				LET vulns = (
					FOR cve, edge IN 1..1 OUTBOUND releaseDoc release2cve
						RETURN {
							cve_id: cve.id,
							severity_rating: cve.database_specific.severity_rating,
							package: edge.package_purl
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
			CveID          string `json:"cve_id"`
			SeverityRating string `json:"severity_rating"`
			Package        string `json:"package"`
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

			// NO VALIDATION NEEDED - edges are pre-validated during ingestion
			var validVulns []map[string]interface{}

			for _, v := range res.Vulns {
				validVulns = append(validVulns, map[string]interface{}{
					"cve_id":          v.CveID,
					"severity_rating": v.SeverityRating,
					"package":         v.Package,
				})
			}
			releaseVulnMap[res.Name+":"+res.Version] = validVulns
		}
	}

	// ========================================================================
	// STEP 4: Assembly
	// Aggregate vulns for each endpoint, calculating deltas
	// FIXED: Move deduplication OUTSIDE the service loop to deduplicate across ALL services
	// ========================================================================

	var finalEndpoints []map[string]interface{}

	for _, ep := range endpointsInv {
		var releasesList []map[string]interface{}

		// Aggregate Counts per Severity for Current and Previous states
		currCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		prevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}

		// FIX: Move deduplication maps OUTSIDE the service loop to deduplicate across ALL services
		seen := make(map[string]bool)
		seenPrev := make(map[string]bool)

		for _, svc := range ep.Services {
			// 1. Current Vulnerabilities
			currKey := svc.Name + ":" + svc.Current.Version
			currVulns := releaseVulnMap[currKey]

			for _, v := range currVulns {
				cveID := v["cve_id"].(string)

				// Ensure we handle package info for deduplication
				pkg := ""
				if p, ok := v["package"].(string); ok {
					pkg = p
				}
				// Use composite key to count Instances (matching Details view)
				dedupKey := cveID + ":" + pkg

				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true

				rating := v["severity_rating"].(string)
				switch rating {
				case "CRITICAL":
					currCounts["critical"]++
				case "HIGH":
					currCounts["high"]++
				case "MEDIUM":
					currCounts["medium"]++
				case "LOW":
					currCounts["low"]++
				}
			}

			// 2. Previous Vulnerabilities (if exists)
			if svc.Previous != nil {
				prevKey := svc.Name + ":" + svc.Previous.Version
				prevVulns := releaseVulnMap[prevKey]

				for _, v := range prevVulns {
					cveID := v["cve_id"].(string)

					pkg := ""
					if p, ok := v["package"].(string); ok {
						pkg = p
					}
					dedupKey := cveID + ":" + pkg

					if seenPrev[dedupKey] {
						continue
					}
					seenPrev[dedupKey] = true

					rating := v["severity_rating"].(string)
					switch rating {
					case "CRITICAL":
						prevCounts["critical"]++
					case "HIGH":
						prevCounts["high"]++
					case "MEDIUM":
						prevCounts["medium"]++
					case "LOW":
						prevCounts["low"]++
					}
				}
			}

			releasesList = append(releasesList, map[string]interface{}{
				"release_name":    svc.Name,
				"release_version": svc.Current.Version,
			})
		}

		// Construct stats
		totalVulnerabilities := map[string]interface{}{
			"critical": currCounts["critical"],
			"high":     currCounts["high"],
			"medium":   currCounts["medium"],
			"low":      currCounts["low"],
		}

		finalEndpoints = append(finalEndpoints, map[string]interface{}{
			"endpoint_name":         ep.EndpointName,
			"endpoint_url":          ep.EndpointURL,
			"endpoint_type":         ep.EndpointType,
			"environment":           ep.Environment,
			"status":                ep.Status,
			"last_sync":             ep.LastSync,
			"release_count":         ep.ReleaseCount,
			"total_vulnerabilities": totalVulnerabilities,
			"releases":              releasesList,
		})
	}

	return finalEndpoints, nil
}

// Helper function to convert generic map structure to models.Affected for util functions
func convertToModelsAffected(allAffected []map[string]interface{}) []models.Affected {
	var result []models.Affected
	for _, affectedMap := range allAffected {
		// Convert map to JSON bytes then to struct to ensure proper field mapping
		bytes, err := json.Marshal(affectedMap)
		if err != nil {
			continue
		}
		var affected models.Affected
		if err := json.Unmarshal(bytes, &affected); err == nil {
			result = append(result, affected)
		}
	}
	return result
}
