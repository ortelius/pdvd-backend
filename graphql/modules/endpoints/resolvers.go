// Package endpoints implements the resolvers for endpoint data.
package endpoints

import (
	"context"
	"net/url"

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

// ResolveEndpointDetails - returns detailed endpoint information with vulnerabilities
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
	// Fetch vulns using original robust AQL filtering
	// ========================================================================

	// Map to store results: "name:version" -> []VulnMatch
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
				
				// Get Dependency Count
				LET dependencyCount = (
					FILTER sbomData != null
					FOR edge IN sbom2purl
						FILTER edge._from == sbomData.id
						COLLECT fullPurl = edge.full_purl
						RETURN 1
				)
				
				// Get Vulnerabilities using Original Robust Filter
				LET vulns = (
					FILTER sbomData != null
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
								summary: cve.summary,
								severity_score: cve.database_specific.cvss_base_score,
								severity_rating: cve.database_specific.severity_rating,
								package: purl.purl,
								affected_version: sbomEdge.version,
								full_purl: sbomEdge.full_purl,
								all_affected: matchedAffected,
								// ORIGINAL LOGIC: Only validate in Go if AQL couldn't decide (majors are null)
								needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
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
			CveID           string            `json:"cve_id"`
			Summary         string            `json:"summary"`
			SeverityScore   float64           `json:"severity_score"`
			SeverityRating  string            `json:"severity_rating"`
			Package         string            `json:"package"`
			AffectedVersion string            `json:"affected_version"`
			FullPurl        string            `json:"full_purl"`
			AllAffected     []models.Affected `json:"all_affected"`
			NeedsValidation bool              `json:"needs_validation"`
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

			// Validate and Store
			var validVulns []map[string]interface{}
			seen := make(map[string]bool)

			for _, v := range res.Vulns {
				// 1. Conditional Go-side Validation (Restored behavior)
				// Only validate if AQL flagged it as needed
				if v.NeedsValidation {
					if len(v.AllAffected) > 0 {
						if !isVersionAffectedAny(v.AffectedVersion, v.AllAffected) {
							continue
						}
					}
				}

				// 2. Local Deduplication for this release
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
					"fixed_in":         util.ExtractApplicableFixedVersion(v.AffectedVersion, v.AllAffected),
					"dependency_count": res.DependencyCount, // Store ref
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
func ResolveSyncedEndpoints(db database.DBConnection, limit int) ([]map[string]interface{}, error) {
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
					
					RETURN {
						name: releaseName,
						current: current,
						previous: previous
					}
			)
			
			// Only return endpoints that actually have services
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
	// Fetch vulns using original robust AQL filtering
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
							
							// ORIGINAL ROBUST FILTER
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
								// ORIGINAL LOGIC: Only validate in Go if AQL couldn't decide
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

			// Go-side Validation & Optimization
			var validVulns []map[string]interface{}

			for _, v := range res.Vulns {
				// Validation
				if v.NeedsValidation {
					if len(v.AllAffected) > 0 {
						if !isVersionAffectedAny(v.AffectedVersion, v.AllAffected) {
							continue
						}
					}
				}

				validVulns = append(validVulns, map[string]interface{}{
					"cve_id":          v.CveID,
					"severity_rating": v.SeverityRating,
				})
			}
			releaseVulnMap[res.Name+":"+res.Version] = validVulns
		}
	}

	// ========================================================================
	// STEP 4: Assembly
	// Aggregate vulns for each endpoint, calculating deltas
	// ========================================================================

	var finalEndpoints []map[string]interface{}

	for _, ep := range endpointsInv {
		var releasesList []map[string]interface{}

		// Aggregate Counts per Severity for Current and Previous states
		currCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		prevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}

		for _, svc := range ep.Services {
			// 1. Current Vulnerabilities
			currKey := svc.Name + ":" + svc.Current.Version
			currVulns := releaseVulnMap[currKey]

			// Deduplicate by CVE ID per service release (standard practice)
			// Note: If you want endpoint-wide deduplication, you move this map outside
			// but usually deltas are summed per service.
			// Assuming simple sum for now as per original logic structure.
			seen := make(map[string]bool)
			for _, v := range currVulns {
				cveID := v["cve_id"].(string)
				if seen[cveID] {
					continue
				}
				seen[cveID] = true

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

				seenPrev := make(map[string]bool)
				for _, v := range prevVulns {
					cveID := v["cve_id"].(string)
					if seenPrev[cveID] {
						continue
					}
					seenPrev[cveID] = true

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

		// Construct stats (Option A: Counts only to match schema)
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
