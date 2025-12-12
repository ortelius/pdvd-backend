// package main provides the entry point and API handlers for the pdvd-backend/v12 microservice,
// including logic for processing releases, SBOMs, handling sync operations, and serving the GraphQL API.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/graphql-go/graphql"
	"github.com/ortelius/pdvd-backend/v12/database"
	gqlschema "github.com/ortelius/pdvd-backend/v12/graphql"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/ortelius/pdvd-backend/v12/util"
)

var db database.DBConnection

// ReleaseWithSBOMResponse returns the result of POST operations
type ReleaseWithSBOMResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ReleaseListItem represents a simplified release for list view
type ReleaseListItem struct {
	Key     string `json:"_key"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SyncRequest represents the request body for creating a sync
type SyncRequest struct {
	ReleaseName    string `json:"release_name"`
	ReleaseVersion string `json:"release_version"`
	EndpointName   string `json:"endpoint_name"`
	SyncStatus     string `json:"sync_status,omitempty"`
	SyncMessage    string `json:"sync_message,omitempty"`
}

// SyncResponse represents the response for sync operations
type SyncResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	SyncKey string `json:"sync_key,omitempty"`
}

// edgeInfo holds edge information for batch processing
type edgeInfo struct {
	from     string
	to       string
	version  string
	fullPurl string
}

// getSBOMContentHash calculates SHA256 hash of SBOM content
func getSBOMContentHash(sbom model.SBOM) string {
	hash := sha256.Sum256(sbom.Content)
	return hex.EncodeToString(hash[:])
}

// populateContentSha sets the ContentSha field based on project type
func populateContentSha(release *model.ProjectRelease) {
	// Use DockerSha for docker/container projects, otherwise use GitCommit
	if release.ProjectType == "docker" || release.ProjectType == "container" {
		if release.DockerSha != "" {
			release.ContentSha = release.DockerSha
		} else if release.GitCommit != "" {
			// Fallback to GitCommit if DockerSha not available
			release.ContentSha = release.GitCommit
		}
	} else {
		// For all other project types, use GitCommit
		if release.GitCommit != "" {
			release.ContentSha = release.GitCommit
		} else if release.DockerSha != "" {
			// Fallback to DockerSha if GitCommit not available
			release.ContentSha = release.DockerSha
		}
	}
}

// processSBOMComponents extracts PURLs from SBOM and creates hub-spoke relationships
// Now uses batch processing for better performance
func processSBOMComponents(ctx context.Context, sbom model.SBOM, sbomID string) error {
	// Parse SBOM content to extract components
	var sbomData struct {
		Components []struct {
			Purl string `json:"purl"`
		} `json:"components"`
	}

	if err := json.Unmarshal(sbom.Content, &sbomData); err != nil {
		return err
	}

	// Step 1: Collect and process all PURLs
	type purlInfo struct {
		basePurl     string
		version      string
		fullPurl     string
		versionMajor *int
		versionMinor *int
		versionPatch *int
		ecosystem    string
	}

	var purlInfos []purlInfo
	basePurlSet := make(map[string]bool) // For deduplication

	for _, component := range sbomData.Components {
		if component.Purl == "" {
			continue
		}

		// Validate and clean PURL format
		cleanedPurl, err := util.CleanPURL(component.Purl)
		if err != nil {
			// Log but continue with other PURLs
			log.Printf("Failed to clean PURL %s: %v", component.Purl, err)
			continue
		}

		// Parse to extract version
		parsed, err := util.ParsePURL(cleanedPurl)
		if err != nil {
			log.Printf("Failed to parse PURL %s: %v", cleanedPurl, err)
			continue
		}

		// Get base PURL (without version) for hub matching
		basePurl, err := util.GetBasePURL(cleanedPurl)
		if err != nil {
			log.Printf("Failed to get base PURL from %s: %v", cleanedPurl, err)
			continue
		}

		versionParsed := util.ParseSemanticVersion(parsed.Version)

		purlInfos = append(purlInfos, purlInfo{
			basePurl:     basePurl,
			version:      parsed.Version,
			fullPurl:     cleanedPurl,
			versionMajor: versionParsed.Major,
			versionMinor: versionParsed.Minor,
			versionPatch: versionParsed.Patch,
			ecosystem:    parsed.Type,
		})

		basePurlSet[basePurl] = true
	}

	if len(purlInfos) == 0 {
		return nil // No valid PURLs to process
	}

	// Step 2: Batch find/create all unique base PURLs
	uniqueBasePurls := make([]string, 0, len(basePurlSet))
	for basePurl := range basePurlSet {
		uniqueBasePurls = append(uniqueBasePurls, basePurl)
	}

	purlIDMap, err := batchFindOrCreatePURLs(ctx, uniqueBasePurls)
	if err != nil {
		return err
	}

	// Step 3: Prepare all edges for batch insertion

	var edgesToCheck []edgeInfo
	edgeCheckMap := make(map[string]bool) // For deduplication: "from:to:version"

	for _, info := range purlInfos {
		purlID, exists := purlIDMap[info.basePurl]
		if !exists {
			log.Printf("Warning: PURL ID not found for base PURL %s", info.basePurl)
			continue
		}

		// Create unique key for edge deduplication
		edgeKey := sbomID + ":" + purlID + ":" + info.version
		if edgeCheckMap[edgeKey] {
			continue // Skip duplicate
		}
		edgeCheckMap[edgeKey] = true

		edgesToCheck = append(edgesToCheck, edgeInfo{
			from:     sbomID,
			to:       purlID,
			version:  info.version,
			fullPurl: info.fullPurl,
		})
	}

	if len(edgesToCheck) == 0 {
		return nil
	}

	// Check which edges already exist
	existingEdges, err := batchCheckEdgesExist(ctx, "sbom2purl", edgesToCheck)
	if err != nil {
		return err
	}

	// Build edges to insert with version metadata
	var edgesToCreate []map[string]interface{}
	for i, checkEdge := range edgesToCheck {
		edgeKey := checkEdge.from + ":" + checkEdge.to + ":" + checkEdge.version
		if !existingEdges[edgeKey] {
			// Find the original purlInfo for this edge to get version components
			var matchingInfo *purlInfo
			for j := range purlInfos {
				purlID := purlIDMap[purlInfos[j].basePurl]
				if checkEdge.from == sbomID && checkEdge.to == purlID && checkEdge.version == purlInfos[j].version {
					matchingInfo = &purlInfos[j]
					break
				}
			}

			edge := map[string]interface{}{
				"_from":     edgesToCheck[i].from,
				"_to":       edgesToCheck[i].to,
				"version":   edgesToCheck[i].version,
				"full_purl": edgesToCheck[i].fullPurl,
			}

			if matchingInfo != nil {
				edge["ecosystem"] = matchingInfo.ecosystem
				if matchingInfo.versionMajor != nil {
					edge["version_major"] = *matchingInfo.versionMajor
				}
				if matchingInfo.versionMinor != nil {
					edge["version_minor"] = *matchingInfo.versionMinor
				}
				if matchingInfo.versionPatch != nil {
					edge["version_patch"] = *matchingInfo.versionPatch
				}
			}

			edgesToCreate = append(edgesToCreate, edge)
		}
	}

	if len(edgesToCreate) > 0 {
		err = batchInsertEdges(ctx, "sbom2purl", edgesToCreate)
		if err != nil {
			return err
		}
	}

	return nil
}

// batchFindOrCreatePURLs finds or creates multiple PURLs in a single query
// Returns a map of basePurl -> purlID
func batchFindOrCreatePURLs(ctx context.Context, basePurls []string) (map[string]string, error) {
	if len(basePurls) == 0 {
		return make(map[string]string), nil
	}

	// Single query to upsert all PURLs and return their IDs
	query := `
		FOR purl IN @purls
			LET upsertedPurl = FIRST(
				UPSERT { purl: purl }
				INSERT { purl: purl, objtype: "PURL" }
				UPDATE {} IN purl
				RETURN NEW
			)
			RETURN {
				basePurl: purl,
				purlId: CONCAT("purl/", upsertedPurl._key)
			}
	`

	bindVars := map[string]interface{}{
		"purls": basePurls,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	purlIDMap := make(map[string]string)
	for cursor.HasMore() {
		var result struct {
			BasePurl string `json:"basePurl"`
			PurlID   string `json:"purlId"`
		}
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			return nil, err
		}
		purlIDMap[result.BasePurl] = result.PurlID
	}

	return purlIDMap, nil
}

// batchCheckEdgesExist checks which edges already exist in a single query
// Returns a map of "from:to:version" -> exists
func batchCheckEdgesExist(ctx context.Context, edgeCollection string, edges []edgeInfo) (map[string]bool, error) {
	if len(edges) == 0 {
		return make(map[string]bool), nil
	}

	// Prepare edge data for query
	type edgeCheck struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Version string `json:"version"`
	}

	var edgeChecks []edgeCheck
	for _, edge := range edges {
		edgeChecks = append(edgeChecks, edgeCheck{
			From:    edge.from,
			To:      edge.to,
			Version: edge.version,
		})
	}

	// Single query to check all edges
	query := `
		FOR check IN @edges
			LET exists = (
				FOR e IN @@edgeCollection
					FILTER e._from == check.from 
					   AND e._to == check.to 
					   AND e.version == check.version
					LIMIT 1
					RETURN true
			)
			RETURN {
				key: CONCAT(check.from, ":", check.to, ":", check.version),
				exists: LENGTH(exists) > 0
			}
	`

	bindVars := map[string]interface{}{
		"@edgeCollection": edgeCollection,
		"edges":           edgeChecks,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	existsMap := make(map[string]bool)
	for cursor.HasMore() {
		var result struct {
			Key    string `json:"key"`
			Exists bool   `json:"exists"`
		}
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			return nil, err
		}
		existsMap[result.Key] = result.Exists
	}

	return existsMap, nil
}

// batchInsertEdges inserts multiple edges in a single query
func batchInsertEdges(ctx context.Context, edgeCollection string, edges []map[string]interface{}) error {
	if len(edges) == 0 {
		return nil
	}

	query := `
		FOR edge IN @edges
			INSERT edge INTO @@edgeCollection
	`

	bindVars := map[string]interface{}{
		"@edgeCollection": edgeCollection,
		"edges":           edges,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return err
	}
	cursor.Close()

	return nil
}

// deleteRelease2SBOMEdges deletes all existing release2sbom edges for a given release
func deleteRelease2SBOMEdges(ctx context.Context, releaseID string) error {
	query := `
		FOR e IN release2sbom
			FILTER e._from == @releaseID
			REMOVE e IN release2sbom
	`
	bindVars := map[string]interface{}{
		"releaseID": releaseID,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return err
	}
	cursor.Close()

	return nil
}

// ============================================================================
// CVE Lifecycle Tracking for MTTR Analysis
// ============================================================================

// CVEKey represents a unique CVE occurrence
type CVEKey struct {
	CveID       string
	Package     string
	ReleaseName string
}

// CurrentCVEInfo holds CVE information for current endpoint state
type CurrentCVEInfo struct {
	CVEKey
	SeverityRating string
	SeverityScore  float64
	ReleaseVersion string
}

// CVEInfoTracking holds minimal CVE info for lifecycle tracking
type CVEInfoTracking struct {
	Package        string
	SeverityRating string
	SeverityScore  float64
}

// updateCVELifecycleTracking processes CVE state changes for an endpoint
func updateCVELifecycleTracking(ctx context.Context, endpointName string,
	syncedAt time.Time, updatedReleases map[string]string) error {

	// Step 1: Get CURRENT CVE state for this endpoint
	currentCVEs, err := getCurrentCVEsForEndpoint(ctx, updatedReleases)
	if err != nil {
		return fmt.Errorf("failed to get current CVEs: %w", err)
	}

	// Step 2: Get PREVIOUS CVE state from lifecycle collection
	previousCVEs, err := getPreviousCVEsFromLifecycle(ctx, endpointName)
	if err != nil {
		return fmt.Errorf("failed to get previous CVEs: %w", err)
	}

	// Step 3: Detect NEW CVEs (introduced)
	for cveKey, cveInfo := range currentCVEs {
		if _, existed := previousCVEs[cveKey]; !existed {
			// New CVE detected during sync - already in database
			err := createLifecycleRecord(ctx, endpointName, cveInfo, syncedAt, false)
			if err != nil {
				log.Printf("Failed to create lifecycle record for %s: %v", cveKey, err)
			}
		}
	}

	// Step 4: Detect REMEDIATED CVEs
	for cveKey, existingRecord := range previousCVEs {
		if _, stillExists := currentCVEs[cveKey]; !stillExists {
			// CVE has been remediated
			remediatedVersion := updatedReleases[existingRecord.ReleaseName]
			err := markCVERemediated(ctx, existingRecord, syncedAt, remediatedVersion)
			if err != nil {
				log.Printf("Failed to mark CVE remediated for %s: %v", cveKey, err)
			}
		}
	}

	return nil
}

// getCurrentCVEsForEndpoint fetches all CVEs for the endpoint's current state
func getCurrentCVEsForEndpoint(ctx context.Context, releases map[string]string) (map[string]CurrentCVEInfo, error) {

	result := make(map[string]CurrentCVEInfo)

	// For each release deployed on this endpoint
	for releaseName, releaseVersion := range releases {
		// Get CVEs for this release (reuse existing vulnerability query)
		cves, err := getCVEsForReleaseTracking(ctx, releaseName, releaseVersion)
		if err != nil {
			log.Printf("Failed to get CVEs for release %s:%s: %v", releaseName, releaseVersion, err)
			continue
		}

		for cveID, cveInfo := range cves {
			// Create composite key (CVE + Package + Release)
			key := fmt.Sprintf("%s:%s:%s", cveID, cveInfo.Package, releaseName)

			result[key] = CurrentCVEInfo{
				CVEKey: CVEKey{
					CveID:       cveID,
					Package:     cveInfo.Package,
					ReleaseName: releaseName,
				},
				SeverityRating: cveInfo.SeverityRating,
				SeverityScore:  cveInfo.SeverityScore,
				ReleaseVersion: releaseVersion,
			}
		}
	}

	return result, nil
}

// getCVEsForReleaseTracking fetches CVEs for a specific release (simplified for tracking)
func getCVEsForReleaseTracking(ctx context.Context, releaseName, releaseVersion string) (map[string]CVEInfoTracking, error) {
	query := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			LIMIT 1
			
			LET sbomData = (
				FOR s IN 1..1 OUTBOUND release release2sbom
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
							severity_score: cve.database_specific.cvss_base_score,
							package: purl.purl,
							affected_version: sbomEdge.version,
							all_affected: matchedAffected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
			)
			
			RETURN vulns
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    releaseName,
			"version": releaseVersion,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type VulnRaw struct {
		CveID           string        `json:"cve_id"`
		SeverityRating  string        `json:"severity_rating"`
		SeverityScore   float64       `json:"severity_score"`
		Package         string        `json:"package"`
		AffectedVersion string        `json:"affected_version"`
		AllAffected     []interface{} `json:"all_affected"`
		NeedsValidation bool          `json:"needs_validation"`
	}

	result := make(map[string]CVEInfoTracking)
	seen := make(map[string]bool)

	if !cursor.HasMore() {
		return result, nil
	}

	var vulns []VulnRaw
	_, err = cursor.ReadDocument(ctx, &vulns)
	if err != nil {
		return nil, err
	}

	for _, v := range vulns {
		// Simplified validation - in production, use isVersionAffectedAny
		if v.NeedsValidation && len(v.AllAffected) > 0 {
			// Skip validation for tracking purposes - be conservative
			// In production, implement full validation
		}

		key := v.CveID + ":" + v.Package
		if seen[key] {
			continue
		}
		seen[key] = true

		result[v.CveID] = CVEInfoTracking{
			Package:        v.Package,
			SeverityRating: v.SeverityRating,
			SeverityScore:  v.SeverityScore,
		}
	}

	return result, nil
}

// getPreviousCVEsFromLifecycle retrieves open CVEs for this endpoint
func getPreviousCVEsFromLifecycle(ctx context.Context,
	endpointName string) (map[string]model.CVELifecycleEvent, error) {

	query := `
		FOR record IN cve_lifecycle
			FILTER record.endpoint_name == @endpoint_name
			FILTER record.is_remediated == false
			RETURN record
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"endpoint_name": endpointName,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	result := make(map[string]model.CVELifecycleEvent)

	for cursor.HasMore() {
		var record model.CVELifecycleEvent
		_, err := cursor.ReadDocument(ctx, &record)
		if err != nil {
			continue
		}

		// Create same composite key
		key := fmt.Sprintf("%s:%s:%s", record.CveID, record.Package, record.ReleaseName)
		result[key] = record
	}

	return result, nil
}

// createLifecycleRecord creates a new CVE lifecycle tracking record
func createLifecycleRecord(ctx context.Context, endpointName string,
	cveInfo CurrentCVEInfo, introducedAt time.Time, disclosedAfterDeployment bool) error {

	record := model.CVELifecycleEvent{
		CveID:                    cveInfo.CveID,
		EndpointName:             endpointName,
		ReleaseName:              cveInfo.ReleaseName,
		Package:                  cveInfo.Package,
		SeverityRating:           cveInfo.SeverityRating,
		SeverityScore:            cveInfo.SeverityScore,
		IntroducedAt:             introducedAt,
		IntroducedVersion:        cveInfo.ReleaseVersion,
		IsRemediated:             false,
		DisclosedAfterDeployment: disclosedAfterDeployment,
		ObjType:                  "CVELifecycleEvent",
		CreatedAt:                time.Now(),
		UpdatedAt:                time.Now(),
	}

	_, err := db.Collections["cve_lifecycle"].CreateDocument(ctx, record)
	return err
}

// markCVERemediated updates a lifecycle record to mark CVE as fixed
func markCVERemediated(ctx context.Context, existingRecord model.CVELifecycleEvent,
	remediatedAt time.Time, remediatedVersion string) error {

	daysToRemediate := remediatedAt.Sub(existingRecord.IntroducedAt).Hours() / 24

	update := map[string]interface{}{
		"remediated_at":      remediatedAt,
		"remediated_version": remediatedVersion,
		"days_to_remediate":  daysToRemediate,
		"is_remediated":      true,
		"updated_at":         time.Now(),
	}

	_, err := db.Collections["cve_lifecycle"].UpdateDocument(ctx, existingRecord.Key, update)
	return err
}

// ============================================================================
// GraphQL Handler
// ============================================================================

// GraphQLHandler handles GraphQL requests
func GraphQLHandler(schema graphql.Schema) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var params struct {
			Query         string                 `json:"query"`
			OperationName string                 `json:"operationName"`
			Variables     map[string]interface{} `json:"variables"`
		}

		if err := c.BodyParser(&params); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"errors": []map[string]interface{}{
					{
						"message": "Invalid request body",
					},
				},
			})
		}

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  params.Query,
			VariableValues: params.Variables,
			OperationName:  params.OperationName,
		})

		if len(result.Errors) > 0 {
			log.Printf("GraphQL errors: %v", result.Errors)
		}

		return c.JSON(result)
	}
}

// ============================================================================
// POST Handlers
// ============================================================================

// PostReleaseWithSBOM handles POST requests for creating a release with its SBOM
func PostReleaseWithSBOM(c *fiber.Ctx) error {
	var req model.ReleaseWithSBOM

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Invalid request body: " + err.Error(),
		})
	}

	// Validate required fields for Release
	if req.Name == "" || req.Version == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Release name and version are required fields",
		})
	}

	// Validate SBOM content
	if len(req.SBOM.Content) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "SBOM content is required",
		})
	}

	// Validate SBOM content is valid JSON
	var sbomContent interface{}
	if err := json.Unmarshal(req.SBOM.Content, &sbomContent); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "SBOM content must be valid JSON: " + err.Error(),
		})
	}

	// Set ObjType if not already set
	if req.ObjType == "" {
		req.ObjType = "ProjectRelease"
	}
	if req.SBOM.ObjType == "" {
		req.SBOM.ObjType = "SBOM"
	}

	// Parse and set version components from the version string
	req.ParseAndSetVersion()

	ctx := context.Background()

	// ============================================================================
	// HYBRID APPROACH: Composite key for Release, Content hash for SBOM
	// ============================================================================

	// Populate ContentSha based on project type
	populateContentSha(&req.ProjectRelease)

	// Validate ContentSha is set
	if req.ContentSha == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "ContentSha is required (GitCommit or DockerSha must be provided)",
		})
	}

	// Check for existing release by composite natural key (name + version + contentsha)
	existingReleaseKey, err := database.FindReleaseByCompositeKey(ctx, db.Database,
		req.Name,
		req.Version,
		req.ContentSha,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to check for existing release: " + err.Error(),
		})
	}

	var releaseID string

	if existingReleaseKey != "" {
		// Release already exists, use existing key
		releaseID = "release/" + existingReleaseKey
		req.Key = existingReleaseKey
	} else {
		// Save new ProjectRelease to ArangoDB
		releaseMeta, err := db.Collections["release"].CreateDocument(ctx, req.ProjectRelease)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
				Success: false,
				Message: "Failed to save release: " + err.Error(),
			})
		}
		releaseID = "release/" + releaseMeta.Key
		req.Key = releaseMeta.Key
	}

	// Calculate content hash for SBOM (stored in ContentSha field)
	sbomHash := getSBOMContentHash(req.SBOM)
	req.SBOM.ContentSha = sbomHash

	// Check if SBOM with this content hash already exists
	existingSBOMKey, err := database.FindSBOMByContentHash(ctx, db.Database, sbomHash)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to check for existing SBOM: " + err.Error(),
		})
	}

	var sbomID string

	if existingSBOMKey != "" {
		// SBOM already exists, use existing key
		sbomID = "sbom/" + existingSBOMKey
		req.SBOM.Key = existingSBOMKey
	} else {
		// Save new SBOM to ArangoDB
		sbomMeta, err := db.Collections["sbom"].CreateDocument(ctx, req.SBOM)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
				Success: false,
				Message: "Failed to save SBOM: " + err.Error(),
			})
		}
		sbomID = "sbom/" + sbomMeta.Key
		req.SBOM.Key = sbomMeta.Key
	}

	// Delete any existing release2sbom edges for this release
	// This ensures a release only has one SBOM (the latest)
	err = deleteRelease2SBOMEdges(ctx, releaseID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to remove old release-sbom relationships: " + err.Error(),
		})
	}

	// Create new edge relationship between release and sbom
	edge := map[string]interface{}{
		"_from": releaseID,
		"_to":   sbomID,
	}
	_, err = db.Collections["release2sbom"].CreateDocument(ctx, edge)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to create release-sbom relationship: " + err.Error(),
		})
	}

	// Process SBOM components and create PURL relationships
	err = processSBOMComponents(ctx, req.SBOM, sbomID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to process SBOM components: " + err.Error(),
		})
	}

	// Determine success message based on whether entities already existed (gocritic fix applied here)
	var message string
	switch {
	case existingReleaseKey != "" && existingSBOMKey != "":
		message = "Release and SBOM already exist (matched by name+version+contentsha and content hash)"
	case existingReleaseKey != "":
		message = "Release already exists (matched by name+version+contentsha), SBOM created and linked"
	case existingSBOMKey != "":
		message = "SBOM already exists (matched by content hash), Release created and linked"
	default:
		message = "Release and SBOM created successfully"
	}

	// Return success response
	return c.Status(fiber.StatusCreated).JSON(ReleaseWithSBOMResponse{
		Success: true,
		Message: message,
	})
}

// PostSyncWithEndpoint handles POST requests for syncing multiple releases (with optional SBOMs) to an endpoint
// Creates/updates releases, processes SBOMs, and creates a sync snapshot with a single timestamp
func PostSyncWithEndpoint(c *fiber.Ctx) error {
	var req model.SyncWithEndpoint

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "Invalid request body: " + err.Error(),
		})
	}

	// Validate required fields
	if req.EndpointName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "endpoint_name is required",
		})
	}

	if len(req.Releases) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "at least one release must be provided",
		})
	}

	ctx := context.Background()

	// Check if endpoint exists
	endpointQuery := `
		FOR e IN endpoint
			FILTER e.name == @name
			LIMIT 1
			RETURN e
	`
	endpointCursor, err := db.Database.Query(ctx, endpointQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name": req.EndpointName,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query endpoint: " + err.Error(),
		})
	}
	defer endpointCursor.Close()

	endpointExists := endpointCursor.HasMore()

	// If endpoint doesn't exist, create it
	if !endpointExists {
		if req.Endpoint.Name == "" || req.Endpoint.EndpointType == "" || req.Endpoint.Environment == "" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"success": false,
				"message": fmt.Sprintf("Endpoint not found: %s. Provide endpoint name, endpoint_type, and environment to create it.", req.EndpointName),
			})
		}

		if req.Endpoint.Name != req.EndpointName {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "Endpoint name in sync does not match endpoint name in endpoint object",
			})
		}

		if req.Endpoint.ObjType == "" {
			req.Endpoint.ObjType = "Endpoint"
		}

		_, err := db.Collections["endpoint"].CreateDocument(ctx, req.Endpoint)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to create endpoint: " + err.Error(),
			})
		}
	}

	// Single timestamp for this complete sync snapshot
	syncedAt := time.Now()

	// Step 1: Get the CURRENT state of the endpoint
	currentStateQuery := `
		FOR sync IN sync
			FILTER sync.endpoint_name == @endpoint_name
			COLLECT release_name = sync.release_name INTO syncGroups = sync
			LET latestSync = (
				FOR s IN syncGroups
					SORT s.synced_at DESC
					LIMIT 1
					RETURN s
			)[0]
			RETURN {
				name: latestSync.release_name,
				version: latestSync.release_version
			}
	`
	currentStateCursor, err := db.Database.Query(ctx, currentStateQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"endpoint_name": req.EndpointName,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query current endpoint state: " + err.Error(),
		})
	}

	currentReleases := make(map[string]string) // name -> version
	for currentStateCursor.HasMore() {
		var rel struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		_, err := currentStateCursor.ReadDocument(ctx, &rel)
		if err != nil {
			continue
		}
		currentReleases[rel.Name] = rel.Version
	}
	currentStateCursor.Close()

	// Step 2: Process each release in the request (create/update with SBOM if provided)
	type releaseResult struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Status  string `json:"status"` // "synced", "created", "created_with_sbom", "updated", "updated_with_sbom", "unchanged", "error"
		SyncKey string `json:"sync_key,omitempty"`
		Message string `json:"message"`
	}

	var results []releaseResult
	updatedReleases := make(map[string]string) // name -> version (the NEW complete state)

	// Start with current state
	for name, version := range currentReleases {
		updatedReleases[name] = version
	}

	// Process releases from request
	for _, relSync := range req.Releases {
		release := relSync.Release
		sbom := relSync.SBOM

		// Validate required fields
		if release.Name == "" || release.Version == "" {
			results = append(results, releaseResult{
				Name:    release.Name,
				Version: release.Version,
				Status:  "error",
				Message: "Release name and version are required",
			})
			continue
		}

		// Clean version
		cleanedVersion := util.CleanVersion(release.Version)
		release.Version = cleanedVersion

		// Parse and set version components
		release.ParseAndSetVersion()

		// Set ObjType
		if release.ObjType == "" {
			release.ObjType = "ProjectRelease"
		}

		// Populate ContentSha
		populateContentSha(&release)

		currentVersion, existsInCurrent := currentReleases[release.Name]

		// Check if this is actually a change
		if existsInCurrent && currentVersion == cleanedVersion && sbom == nil {
			results = append(results, releaseResult{
				Name:    release.Name,
				Version: cleanedVersion,
				Status:  "unchanged",
				Message: "Release already at this version",
			})
			continue
		}

		// Check if release exists in database
		var existingReleaseKey string
		if release.ContentSha != "" {
			existingReleaseKey, err = database.FindReleaseByCompositeKey(ctx, db.Database,
				release.Name, release.Version, release.ContentSha)
			if err != nil {
				results = append(results, releaseResult{
					Name:    release.Name,
					Version: cleanedVersion,
					Status:  "error",
					Message: fmt.Sprintf("Failed to check for existing release: %s", err.Error()),
				})
				continue
			}
		}

		var releaseID string
		releaseCreated := false

		if existingReleaseKey != "" {
			// Release already exists
			releaseID = "release/" + existingReleaseKey
			release.Key = existingReleaseKey
		} else {
			// Create new release
			releaseMeta, err := db.Collections["release"].CreateDocument(ctx, release)
			if err != nil {
				results = append(results, releaseResult{
					Name:    release.Name,
					Version: cleanedVersion,
					Status:  "error",
					Message: fmt.Sprintf("Failed to create release: %s", err.Error()),
				})
				continue
			}
			releaseID = "release/" + releaseMeta.Key
			release.Key = releaseMeta.Key
			releaseCreated = true
		}

		// Process SBOM if provided
		sbomProcessed := false
		if sbom != nil && len(sbom.Content) > 0 {
			// Validate SBOM content is valid JSON
			var sbomContent interface{}
			if err := json.Unmarshal(sbom.Content, &sbomContent); err != nil {
				results = append(results, releaseResult{
					Name:    release.Name,
					Version: cleanedVersion,
					Status:  "error",
					Message: fmt.Sprintf("SBOM content must be valid JSON: %s", err.Error()),
				})
				continue
			}

			// Set SBOM ObjType
			if sbom.ObjType == "" {
				sbom.ObjType = "SBOM"
			}

			// Calculate content hash for SBOM
			sbomHash := getSBOMContentHash(*sbom)
			sbom.ContentSha = sbomHash

			// Check if SBOM exists
			existingSBOMKey, err := database.FindSBOMByContentHash(ctx, db.Database, sbomHash)
			if err != nil {
				results = append(results, releaseResult{
					Name:    release.Name,
					Version: cleanedVersion,
					Status:  "error",
					Message: fmt.Sprintf("Failed to check for existing SBOM: %s", err.Error()),
				})
				continue
			}

			var sbomID string

			if existingSBOMKey != "" {
				// SBOM already exists
				sbomID = "sbom/" + existingSBOMKey
				sbom.Key = existingSBOMKey
			} else {
				// Create new SBOM
				sbomMeta, err := db.Collections["sbom"].CreateDocument(ctx, *sbom)
				if err != nil {
					results = append(results, releaseResult{
						Name:    release.Name,
						Version: cleanedVersion,
						Status:  "error",
						Message: fmt.Sprintf("Failed to save SBOM: %s", err.Error()),
					})
					continue
				}
				sbomID = "sbom/" + sbomMeta.Key
				sbom.Key = sbomMeta.Key
			}

			// Delete old release2sbom edges
			err = deleteRelease2SBOMEdges(ctx, releaseID)
			if err != nil {
				results = append(results, releaseResult{
					Name:    release.Name,
					Version: cleanedVersion,
					Status:  "error",
					Message: fmt.Sprintf("Failed to remove old release-sbom relationships: %s", err.Error()),
				})
				continue
			}

			// Create new edge relationship
			edge := map[string]interface{}{
				"_from": releaseID,
				"_to":   sbomID,
			}
			_, err = db.Collections["release2sbom"].CreateDocument(ctx, edge)
			if err != nil {
				results = append(results, releaseResult{
					Name:    release.Name,
					Version: cleanedVersion,
					Status:  "error",
					Message: fmt.Sprintf("Failed to create release-sbom relationship: %s", err.Error()),
				})
				continue
			}

			// Process SBOM components
			err = processSBOMComponents(ctx, *sbom, sbomID)
			if err != nil {
				results = append(results, releaseResult{
					Name:    release.Name,
					Version: cleanedVersion,
					Status:  "error",
					Message: fmt.Sprintf("Failed to process SBOM components: %s", err.Error()),
				})
				continue
			}

			sbomProcessed = true
		}

		// Add to updated state
		updatedReleases[release.Name] = cleanedVersion

		// Determine status message
		statusMsg := ""
		switch {
		case releaseCreated && sbomProcessed:
			statusMsg = "created_with_sbom"
		case releaseCreated:
			statusMsg = "created"
		case sbomProcessed:
			statusMsg = "updated_with_sbom"
		default:
			statusMsg = "updated"
		}

		results = append(results, releaseResult{
			Name:    release.Name,
			Version: cleanedVersion,
			Status:  statusMsg,
			Message: "Release processed successfully",
		})
	}

	// Step 3: Create sync records for the COMPLETE new state
	// REVISED: Always create new sync records to maintain history (Trend Analysis)
	var syncKeys []string
	syncedCount := 0

	for releaseName, releaseVersion := range updatedReleases {
		// Fetch full metadata for this release
		releaseQuery := `
			FOR r IN release
				FILTER r.name == @name && r.version == @version
				LIMIT 1
				RETURN {
					name: r.name,
					version: r.version,
					version_major: r.version_major,
					version_minor: r.version_minor,
					version_patch: r.version_patch,
					version_prerelease: r.version_prerelease
				}
		`
		releaseCursor, err := db.Database.Query(ctx, releaseQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"name":    releaseName,
				"version": releaseVersion,
			},
		})
		if err != nil {
			continue
		}

		if !releaseCursor.HasMore() {
			releaseCursor.Close()
			continue
		}

		type releaseMetadata struct {
			Name              string `json:"name"`
			Version           string `json:"version"`
			VersionMajor      *int   `json:"version_major"`
			VersionMinor      *int   `json:"version_minor"`
			VersionPatch      *int   `json:"version_patch"`
			VersionPrerelease string `json:"version_prerelease"`
		}

		var relMeta releaseMetadata
		_, err = releaseCursor.ReadDocument(ctx, &relMeta)
		releaseCursor.Close()
		if err != nil {
			continue
		}

		// Create sync record object
		sync := map[string]interface{}{
			"release_name":    relMeta.Name,
			"release_version": relMeta.Version,
			"endpoint_name":   req.EndpointName,
			"synced_at":       syncedAt, // Timestamp is key for history
			"objtype":         "Sync",
		}

		if relMeta.VersionMajor != nil {
			sync["release_version_major"] = *relMeta.VersionMajor
		}
		if relMeta.VersionMinor != nil {
			sync["release_version_minor"] = *relMeta.VersionMinor
		}
		if relMeta.VersionPatch != nil {
			sync["release_version_patch"] = *relMeta.VersionPatch
		}
		if relMeta.VersionPrerelease != "" {
			sync["release_version_prerelease"] = relMeta.VersionPrerelease
		}

		// Insert new document (maintain history) instead of updating
		syncMeta, err := db.Collections["sync"].CreateDocument(ctx, sync)
		if err != nil {
			// Update result with error if this was a processed release
			for i := range results {
				if results[i].Name == relMeta.Name && results[i].Version == relMeta.Version {
					results[i].Status = "error"
					results[i].Message = fmt.Sprintf("Failed to save sync: %s", err.Error())
				}
			}
			continue
		}

		syncKeys = append(syncKeys, syncMeta.Key)
		syncedCount++

		// Update result with sync key if this was a processed release
		for i := range results {
			if results[i].Name == relMeta.Name && results[i].Version == relMeta.Version && results[i].Status != "unchanged" {
				results[i].SyncKey = syncMeta.Key
			}
		}
	}

	// Step 4: Update CVE lifecycle tracking
	err = updateCVELifecycleTracking(ctx, req.EndpointName, syncedAt, updatedReleases)
	if err != nil {
		log.Printf("Warning: Failed to update CVE lifecycle tracking: %v", err)
		// Don't fail the sync, but log the error
	}

	// Build response summary
	createdCount := 0
	createdWithSbomCount := 0
	updatedCount := 0
	updatedWithSbomCount := 0
	unchangedCount := 0
	errorCount := 0

	for _, result := range results {
		switch result.Status {
		case "created":
			createdCount++
		case "created_with_sbom":
			createdWithSbomCount++
		case "updated":
			updatedCount++
		case "updated_with_sbom":
			updatedWithSbomCount++
		case "unchanged":
			unchangedCount++
		case "error":
			errorCount++
		}
	}

	totalCreated := createdCount + createdWithSbomCount
	totalUpdated := updatedCount + updatedWithSbomCount

	// Determine overall success
	overallSuccess := syncedCount > 0
	statusCode := fiber.StatusCreated
	if syncedCount == 0 {
		statusCode = fiber.StatusBadRequest
	} else if errorCount > 0 {
		statusCode = fiber.StatusMultiStatus // 207 - partial success
	}

	message := fmt.Sprintf("Created sync snapshot with %d releases for endpoint %s", syncedCount, req.EndpointName)
	if !endpointExists {
		message += " (endpoint created)"
	}
	if totalCreated > 0 {
		message += fmt.Sprintf(", %d created", totalCreated)
		if createdWithSbomCount > 0 {
			message += fmt.Sprintf(" (%d with SBOM)", createdWithSbomCount)
		}
	}
	if totalUpdated > 0 {
		message += fmt.Sprintf(", %d updated", totalUpdated)
		if updatedWithSbomCount > 0 {
			message += fmt.Sprintf(" (%d with SBOM)", updatedWithSbomCount)
		}
	}
	if unchangedCount > 0 {
		message += fmt.Sprintf(", %d unchanged", unchangedCount)
	}
	if errorCount > 0 {
		message += fmt.Sprintf(", %d errors", errorCount)
	}

	return c.Status(statusCode).JSON(fiber.Map{
		"success":           overallSuccess,
		"message":           message,
		"synced_at":         syncedAt,
		"total_in_request":  len(req.Releases),
		"total_synced":      syncedCount,
		"created":           totalCreated,
		"created_with_sbom": createdWithSbomCount,
		"updated":           totalUpdated,
		"updated_with_sbom": updatedWithSbomCount,
		"unchanged":         unchangedCount,
		"errors":            errorCount,
		"results":           results,
	})
}

// ============================================================================
// Admin Endpoints - MTTR Backfill
// ============================================================================

var backfillRunning = false
var backfillProgress = ""

// PostBackfillMTTR triggers the CVE lifecycle backfill process
func PostBackfillMTTR(c *fiber.Ctx) error {
	if backfillRunning {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"success": false,
			"message": "Backfill already in progress",
			"status":  backfillProgress,
		})
	}

	type BackfillRequest struct {
		DaysBack int `json:"days_back"`
	}

	var req BackfillRequest
	if err := c.BodyParser(&req); err != nil {
		req.DaysBack = 90 // Default to 90 days
	}

	if req.DaysBack <= 0 || req.DaysBack > 365 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "days_back must be between 1 and 365",
		})
	}

	// Run backfill in background
	go func() {
		backfillRunning = true
		backfillProgress = fmt.Sprintf("Starting backfill for %d days...", req.DaysBack)

		ctx := context.Background()
		cutoffDate := time.Now().AddDate(0, 0, -req.DaysBack)

		log.Printf("Starting CVE lifecycle backfill for last %d days...", req.DaysBack)

		// Fetch sync history
		syncQuery := `
			FOR sync IN sync
				FILTER sync.synced_at >= @cutoffDate
				SORT sync.synced_at ASC
				RETURN {
					endpoint_name: sync.endpoint_name,
					release_name: sync.release_name,
					release_version: sync.release_version,
					synced_at: sync.synced_at
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
				"cutoffDate": cutoffDate,
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
			_, err := cursor.ReadDocument(ctx, &sync)
			if err != nil {
				continue
			}
			allSyncs = append(allSyncs, sync)
		}

		backfillProgress = fmt.Sprintf("Processing %d sync events...", len(allSyncs))
		log.Printf("Processing %d sync events", len(allSyncs))

		// Group by endpoint
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

			// Track CVE state
			currentCVEs := make(map[string]CurrentCVEInfo)

			for _, sync := range syncs {
				// Get CVEs for this release
				newCVEs, err := getCVEsForReleaseTracking(ctx, sync.ReleaseName, sync.ReleaseVersion)
				if err != nil {
					continue
				}

				// Build new state
				newState := make(map[string]CurrentCVEInfo)
				for cveID, cveInfo := range newCVEs {
					key := fmt.Sprintf("%s:%s:%s", cveID, cveInfo.Package, sync.ReleaseName)
					newState[key] = CurrentCVEInfo{
						CVEKey: CVEKey{
							CveID:       cveID,
							Package:     cveInfo.Package,
							ReleaseName: sync.ReleaseName,
						},
						SeverityRating: cveInfo.SeverityRating,
						SeverityScore:  cveInfo.SeverityScore,
						ReleaseVersion: sync.ReleaseVersion,
					}
				}

				// Detect introductions
				for key, cveInfo := range newState {
					if _, existed := currentCVEs[key]; !existed {
						err := createLifecycleRecord(ctx, endpointName, cveInfo, sync.SyncedAt, false)
						if err == nil {
							totalIntroductions++
						}
					}
				}

				// Detect remediations
				for key, cveInfo := range currentCVEs {
					if _, stillExists := newState[key]; !stillExists {
						err := markCVERemediated(ctx, model.CVELifecycleEvent{
							EndpointName: endpointName,
							CveID:        cveInfo.CveID,
							Package:      cveInfo.Package,
							ReleaseName:  cveInfo.ReleaseName,
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
	}()

	return c.JSON(fiber.Map{
		"success": true,
		"message": fmt.Sprintf("Backfill started for %d days of history", req.DaysBack),
		"status":  "processing",
	})
}

// GetBackfillStatus returns the current status of any running backfill
func GetBackfillStatus(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"running": backfillRunning,
		"status":  backfillProgress,
	})
}

// ============================================================================
// Main
// ============================================================================

func main() {
	// Initialize database connection
	db = database.InitializeDatabase()

	// Initialize GraphQL schema
	gqlschema.InitDB(db)
	schema, err := gqlschema.CreateSchema()
	if err != nil {
		log.Fatalf("Failed to create GraphQL schema: %v", err)
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:     "pdvd-backend/v12 API v1.0",
		BodyLimit:   50 * 1024 * 1024, // 50MB limit for SBOM uploads
		ReadTimeout: time.Second * 60, // 60 second read timeout for large uploads
	})

	// Middleware
	app.Use(fiberrecover.New())
	app.Use(logger.New())
	app.Use(cors.New())

	// Health check endpoint
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
		})
	})

	// API routes
	api := app.Group("/api/v1")

	// POST endpoints
	api.Post("/releases", PostReleaseWithSBOM)
	api.Post("/sync", PostSyncWithEndpoint)

	// GraphQL endpoint
	api.Post("/graphql", GraphQLHandler(schema))

	// Admin endpoints for MTTR backfill
	admin := api.Group("/admin")
	admin.Post("/backfill-mttr", PostBackfillMTTR)
	admin.Get("/backfill-status", GetBackfillStatus)

	// Get port from environment or default to 3000
	port := os.Getenv("MS_PORT")
	if port == "" {
		port = "3000"
	}

	// Start server
	log.Printf("Starting server on port %s", port)
	log.Printf("GraphQL endpoint available at /api/v1/graphql")
	log.Printf("Admin endpoints available at /api/v1/admin/*")
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
