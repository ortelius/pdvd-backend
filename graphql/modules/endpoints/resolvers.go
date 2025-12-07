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

func ResolveEndpointDetails(db database.DBConnection, endpointName string) (map[string]interface{}, error) {
	ctx := context.Background()

	decodedName, err := url.QueryUnescape(endpointName)
	if err != nil {
		decodedName = endpointName
	}

	query := `
		FOR endpoint IN endpoint
			FILTER endpoint.name == @endpointName
			LIMIT 1
			
			LET syncedReleases = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					COLLECT releaseName = sync.release_name INTO groupedSyncs = sync
					
					LET latestSync = (
						FOR s IN groupedSyncs
							SORT s.release_version_major != null ? s.release_version_major : -1 DESC,
								s.release_version_minor != null ? s.release_version_minor : -1 DESC,
								s.release_version_patch != null ? s.release_version_patch : -1 DESC,
								s.release_version_prerelease != null && s.release_version_prerelease != "" ? 1 : 0 ASC,
								s.release_version_prerelease ASC,
								s.release_version DESC
							LIMIT 1
							RETURN s
					)[0]
					
					LET releaseDoc = (
						FOR r IN release
							FILTER r.name == latestSync.release_name AND r.version == latestSync.release_version
							LIMIT 1
							RETURN r
					)[0]
					
					FILTER releaseDoc != null
					
					LET sbomData = (
						FOR s IN 1..1 OUTBOUND releaseDoc release2sbom
							LIMIT 1
							RETURN { id: s._id }
					)[0]
					
					LET dependencyCount = (
						FILTER sbomData != null
						FOR edge IN sbom2purl
							FILTER edge._from == sbomData.id
							COLLECT fullPurl = edge.full_purl
							RETURN 1
					)
					
					LET cveMatches = (
						FILTER sbomData != null
						FOR sbomEdge IN sbom2purl
							FILTER sbomEdge._from == sbomData.id
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
									cve_id: cve.id,
									summary: cve.summary,
									severity_score: cve.database_specific.cvss_base_score,
									severity_rating: cve.database_specific.severity_rating,
									package: purl.purl,
									affected_version: sbomEdge.version,
									full_purl: sbomEdge.full_purl,
									all_affected: matchedAffected,
									needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
								}
					)
					
					LET uniqueCves = (
						FOR match IN cveMatches
							COLLECT cveId = match.cve_id
							RETURN 1
					)
					LET currentVulnCount = LENGTH(uniqueCves)
					
					LET previousSync = (
						FOR s IN groupedSyncs
							FILTER s != latestSync
							SORT s.release_version_major != null ? s.release_version_major : -1 DESC,
								s.release_version_minor != null ? s.release_version_minor : -1 DESC,
								s.release_version_patch != null ? s.release_version_patch : -1 DESC,
								s.release_version_prerelease != null && s.release_version_prerelease != "" ? 1 : 0 ASC,
								s.release_version_prerelease ASC,
								s.release_version DESC
							LIMIT 1
							RETURN s
					)[0]
					
					LET prevVulnCount = previousSync != null ? (
						LET prevRelease = (
							FOR r IN release
								FILTER r.name == previousSync.release_name AND r.version == previousSync.release_version
								LIMIT 1
								RETURN r
						)[0]
						
						FILTER prevRelease != null
						
						LET prevSbomData = (
							FOR s IN 1..1 OUTBOUND prevRelease release2sbom
								LIMIT 1
								RETURN { id: s._id }
						)[0]
						
						FILTER prevSbomData != null
						
						LET prevCveMatches = (
							FOR sbomEdge IN sbom2purl
								FILTER sbomEdge._from == prevSbomData.id
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
									
									RETURN { cve_id: cve.id }
						)
						
						LET prevUniqueCves = (
							FOR match IN prevCveMatches
								COLLECT cveId = match.cve_id
								RETURN 1
						)
						
						RETURN LENGTH(prevUniqueCves)
					)[0] : null
					
					LET vulnerabilityCountDelta = prevVulnCount != null ? (currentVulnCount - prevVulnCount) : null
					
					RETURN {
						release_name: releaseDoc.name,
						release_version: releaseDoc.version,
						openssf_scorecard_score: releaseDoc.openssf_scorecard_score,
						dependency_count: LENGTH(dependencyCount),
						last_sync: latestSync.synced_at,
						vulnerability_count: currentVulnCount,
						vulnerability_count_delta: vulnerabilityCountDelta,
						vulnerabilities: cveMatches
					}
			)
			
			LET totalVulnerabilities = (
				FOR release IN syncedReleases
					FOR vuln IN release.vulnerabilities
						RETURN {
							severity_rating: vuln.severity_rating,
							severity_score: vuln.severity_score
						}
			)
			
			LET criticalCount = LENGTH(
				FOR v IN totalVulnerabilities
					FILTER v.severity_rating == "CRITICAL"
					RETURN 1
			)
			
			LET highCount = LENGTH(
				FOR v IN totalVulnerabilities
					FILTER v.severity_rating == "HIGH"
					RETURN 1
			)
			
			LET mediumCount = LENGTH(
				FOR v IN totalVulnerabilities
					FILTER v.severity_rating == "MEDIUM"
					RETURN 1
			)
			
			LET lowCount = LENGTH(
				FOR v IN totalVulnerabilities
					FILTER v.severity_rating == "LOW"
					RETURN 1
			)
			
			LET totalDelta = SUM(
				FOR release IN syncedReleases
					FILTER release.vulnerability_count_delta != null
					RETURN release.vulnerability_count_delta
			)
			
			LET latestSyncTime = MAX(
				FOR release IN syncedReleases
					RETURN release.last_sync
			)
			
			RETURN {
				endpoint_name: endpoint.name,
				endpoint_url: endpoint.name,
				endpoint_type: endpoint.endpoint_type,
				environment: endpoint.environment,
				status: "active",
				last_sync: latestSyncTime,
				total_vulnerabilities: {
					critical: criticalCount,
					high: highCount,
					medium: mediumCount,
					low: lowCount
				},
				vulnerability_count_delta: totalDelta,
				releases: syncedReleases
			}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"endpointName": decodedName,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type VulnMatch struct {
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

	type ReleaseData struct {
		ReleaseName             string      `json:"release_name"`
		ReleaseVersion          string      `json:"release_version"`
		OpenSSFScorecardScore   *float64    `json:"openssf_scorecard_score"`
		DependencyCount         int         `json:"dependency_count"`
		LastSync                string      `json:"last_sync"`
		VulnerabilityCount      int         `json:"vulnerability_count"`
		VulnerabilityCountDelta *int        `json:"vulnerability_count_delta"`
		Vulnerabilities         []VulnMatch `json:"vulnerabilities"`
	}

	type EndpointDetailsResult struct {
		EndpointName            string         `json:"endpoint_name"`
		EndpointURL             string         `json:"endpoint_url"`
		EndpointType            string         `json:"endpoint_type"`
		Environment             string         `json:"environment"`
		Status                  string         `json:"status"`
		LastSync                string         `json:"last_sync"`
		TotalVulnerabilities    map[string]int `json:"total_vulnerabilities"`
		VulnerabilityCountDelta int            `json:"vulnerability_count_delta"`
		Releases                []ReleaseData  `json:"releases"`
	}

	if !cursor.HasMore() {
		return nil, nil
	}

	var result EndpointDetailsResult
	_, err = cursor.ReadDocument(ctx, &result)
	if err != nil {
		return nil, err
	}

	var processedReleases []map[string]interface{}
	for _, release := range result.Releases {
		var processedVulns []map[string]interface{}
		seen := make(map[string]bool)

		for _, vuln := range release.Vulnerabilities {
			if vuln.NeedsValidation && len(vuln.AllAffected) > 0 {
				if !isVersionAffectedAny(vuln.AffectedVersion, vuln.AllAffected) {
					continue
				}
			}

			key := vuln.CveID + ":" + vuln.Package + ":" + vuln.AffectedVersion
			if seen[key] {
				continue
			}
			seen[key] = true

			processedVuln := map[string]interface{}{
				"cve_id":           vuln.CveID,
				"summary":          vuln.Summary,
				"severity_score":   vuln.SeverityScore,
				"severity_rating":  vuln.SeverityRating,
				"package":          vuln.Package,
				"affected_version": vuln.AffectedVersion,
				"full_purl":        vuln.FullPurl,
			}

			if len(vuln.AllAffected) > 0 {
				processedVuln["fixed_in"] = util.ExtractApplicableFixedVersion(vuln.AffectedVersion, vuln.AllAffected)
			}

			processedVulns = append(processedVulns, processedVuln)
		}

		processedReleases = append(processedReleases, map[string]interface{}{
			"release_name":              release.ReleaseName,
			"release_version":           release.ReleaseVersion,
			"openssf_scorecard_score":   release.OpenSSFScorecardScore,
			"dependency_count":          release.DependencyCount,
			"last_sync":                 release.LastSync,
			"vulnerability_count":       release.VulnerabilityCount,
			"vulnerability_count_delta": release.VulnerabilityCountDelta,
			"vulnerabilities":           processedVulns,
		})
	}

	return map[string]interface{}{
		"endpoint_name":             result.EndpointName,
		"endpoint_url":              result.EndpointURL,
		"endpoint_type":             result.EndpointType,
		"environment":               result.Environment,
		"status":                    result.Status,
		"last_sync":                 result.LastSync,
		"total_vulnerabilities":     result.TotalVulnerabilities,
		"vulnerability_count_delta": result.VulnerabilityCountDelta,
		"releases":                  processedReleases,
	}, nil
}

func ResolveSyncedEndpoints(db database.DBConnection, limit int) ([]map[string]interface{}, error) {
	ctx := context.Background()

	query := `
		FOR endpoint IN endpoint
			LET syncedReleases = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					COLLECT releaseName = sync.release_name, releaseVersion = sync.release_version
					RETURN {
						release_name: releaseName,
						release_version: releaseVersion
					}
			)
			
			LET releaseCount = LENGTH(syncedReleases)
			
			LET latestSync = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					SORT sync.synced_at DESC
					LIMIT 1
					RETURN sync.synced_at
			)[0]
			
			LET allVulnerabilities = (
				FOR releaseInfo IN syncedReleases
					FOR release IN release
						FILTER release.name == releaseInfo.release_name AND release.version == releaseInfo.release_version
						LIMIT 1
						
						FOR sbom IN 1..1 OUTBOUND release release2sbom
							FOR sbomEdge IN sbom2purl
								FILTER sbomEdge._from == sbom._id
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
										severity_rating: cve.database_specific.severity_rating
									}
			)
			
			LET criticalCount = LENGTH(
				FOR v IN allVulnerabilities
					FILTER v.severity_rating == "CRITICAL"
					RETURN 1
			)
			
			LET highCount = LENGTH(
				FOR v IN allVulnerabilities
					FILTER v.severity_rating == "HIGH"
					RETURN 1
			)
			
			LET mediumCount = LENGTH(
				FOR v IN allVulnerabilities
					FILTER v.severity_rating == "MEDIUM"
					RETURN 1
			)
			
			LET lowCount = LENGTH(
				FOR v IN allVulnerabilities
					FILTER v.severity_rating == "LOW"
					RETURN 1
			)
			
			LIMIT @limit
			
			RETURN {
				endpoint_name: endpoint.name,
				endpoint_url: endpoint.name,
				endpoint_type: endpoint.endpoint_type,
				environment: endpoint.environment,
				status: "active",
				last_sync: latestSync,
				release_count: releaseCount,
				total_vulnerabilities: {
					critical: criticalCount,
					high: highCount,
					medium: mediumCount,
					low: lowCount
				},
				releases: syncedReleases
			}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"limit": limit,
		},
	})
	if err != nil {
		return []map[string]interface{}{}, nil
	}
	defer cursor.Close()

	var endpoints []map[string]interface{}
	for cursor.HasMore() {
		var endpoint map[string]interface{}
		_, err := cursor.ReadDocument(ctx, &endpoint)
		if err != nil {
			continue
		}
		endpoints = append(endpoints, endpoint)
	}

	if endpoints == nil {
		return []map[string]interface{}{}, nil
	}
	return endpoints, nil
}
