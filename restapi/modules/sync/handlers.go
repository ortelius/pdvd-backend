// Package sync implements the REST API handlers for sync operations.
package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/lifecycle"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/releases"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/sbom"
	"github.com/ortelius/pdvd-backend/v12/util"
)

// PostSyncWithEndpoint handles POST requests for syncing multiple releases to an endpoint
func PostSyncWithEndpoint(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req model.SyncWithEndpoint

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"message": "Invalid request body: " + err.Error(),
			})
		}

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
		endpointExists, err := checkEndpointExists(ctx, db, req.EndpointName)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to query endpoint: " + err.Error(),
			})
		}

		// Create endpoint if it doesn't exist
		if !endpointExists {
			if err := createEndpoint(ctx, db, req); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"success": false,
					"message": err.Error(),
				})
			}
		}

		// Get sync timestamp
		syncedAt := time.Now()
		if !req.SyncedAt.IsZero() {
			syncedAt = req.SyncedAt
		}

		// Step 1: Get current state
		currentReleases, err := getCurrentEndpointState(ctx, db, req.EndpointName)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to query current endpoint state: " + err.Error(),
			})
		}

		// Step 2: Process releases
		results, updatedReleases, err := processReleases(ctx, db, req, currentReleases)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
			})
		}

		// Step 3: Create sync records
		syncedCount, err := createSyncRecords(ctx, db, req.EndpointName, updatedReleases, syncedAt, results)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to create sync records: " + err.Error(),
			})
		}

		// Step 4: Update CVE lifecycle tracking
		for releaseName, releaseVersion := range updatedReleases {
			// Get CVEs for this release from release2cve edges
			sbomCVEs, err := getCVEsForRelease(ctx, db, releaseName, releaseVersion)
			if err != nil {
				fmt.Printf("Warning: Failed to get CVEs for %s version %s: %v\n", releaseName, releaseVersion, err)
				continue
			}

			// Skip if no CVEs found
			if len(sbomCVEs) == 0 {
				continue
			}

			// Process lifecycle tracking for this release
			err = ProcessSync(
				ctx, db,
				req.EndpointName,
				releaseName,
				releaseVersion,
				sbomCVEs,
				syncedAt,
			)
			if err != nil {
				fmt.Printf("Warning: Failed to update CVE lifecycle for %s version %s: %v\n", releaseName, releaseVersion, err)
			}
		}

		// Build response
		return buildSyncResponse(c, results, syncedCount, endpointExists, req.EndpointName, syncedAt)
	}
}

// getCVEsForRelease retrieves CVEs affecting a specific release
func getCVEsForRelease(ctx context.Context, db database.DBConnection, releaseName, releaseVersion string) ([]lifecycle.CVEInfo, error) {
	// FIX: Use DATE_ISO8601 to ensure Published can be parsed if it's missing timezone info
	query := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			LIMIT 1
			
			FOR cve, edge IN 1..1 OUTBOUND release release2cve
				RETURN {
					cve_id: cve.id,
					package: edge.package_purl,
					severity_rating: cve.database_specific.severity_rating,
					severity_score: cve.database_specific.cvss_base_score,
					published: DATE_ISO8601(cve.published)
				}
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

	var cves []lifecycle.CVEInfo
	for cursor.HasMore() {
		var raw struct {
			CveID          string  `json:"cve_id"`
			Package        string  `json:"package"`
			SeverityRating string  `json:"severity_rating"`
			SeverityScore  float64 `json:"severity_score"`
			Published      string  `json:"published"`
		}

		if _, err := cursor.ReadDocument(ctx, &raw); err != nil {
			continue
		}

		var publishedTime time.Time
		if raw.Published != "" {
			if t, err := time.Parse(time.RFC3339, raw.Published); err == nil {
				publishedTime = t
			}
		}

		cves = append(cves, lifecycle.CVEInfo{
			CVEID:          raw.CveID,
			Package:        raw.Package,
			SeverityRating: raw.SeverityRating,
			SeverityScore:  raw.SeverityScore,
			Published:      publishedTime,
			// FIXED: Populate new Release context fields
			ReleaseName:    releaseName,
			ReleaseVersion: releaseVersion,
		})
	}

	return cves, nil
}

// ProcessSync handles sync event and updates lifecycle tracking.
func ProcessSync(
	ctx context.Context,
	db database.DBConnection,
	endpointName string,
	releaseName string,
	releaseVersion string,
	sbomCVEs []lifecycle.CVEInfo,
	syncedAt time.Time,
) error {

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

	// Step 2: Create lifecycle records for all CVEs in this version
	currentCVEMap := make(map[string]lifecycle.CVEInfo)

	for _, cve := range sbomCVEs {
		key := fmt.Sprintf("%s:%s", cve.CVEID, cve.Package)
		currentCVEMap[key] = cve

		// Determine if CVE was disclosed after deployment
		disclosedAfter := !cve.Published.IsZero() && cve.Published.After(syncedAt)

		err := lifecycle.CreateOrUpdateLifecycleRecord(
			ctx, db,
			endpointName,
			releaseName,
			releaseVersion,
			cve,
			syncedAt,
			disclosedAfter,
		)

		if err != nil {
			return fmt.Errorf("failed to create lifecycle record for %s: %w", cve.CVEID, err)
		}
	}

	// Step 3: If not first deployment, compare versions and mark remediations
	if !isFirstDeployment {
		_, err := lifecycle.CompareAndMarkRemediations(
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

func checkEndpointExists(ctx context.Context, db database.DBConnection, endpointName string) (bool, error) {
	query := `FOR e IN endpoint FILTER e.name == @name LIMIT 1 RETURN e`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"name": endpointName},
	})
	if err != nil {
		return false, err
	}
	defer cursor.Close()
	return cursor.HasMore(), nil
}

func createEndpoint(ctx context.Context, db database.DBConnection, req model.SyncWithEndpoint) error {
	if req.Endpoint.Name == "" || req.Endpoint.EndpointType == "" || req.Endpoint.Environment == "" {
		return fmt.Errorf("endpoint not found: %s", req.EndpointName)
	}
	if req.Endpoint.ObjType == "" {
		req.Endpoint.ObjType = "Endpoint"
	}
	req.Endpoint.ParseAndSetNameComponents()
	_, err := db.Collections["endpoint"].CreateDocument(ctx, req.Endpoint)
	return err
}

func getCurrentEndpointState(ctx context.Context, db database.DBConnection, endpointName string) (map[string]string, error) {
	query := `
		FOR sync IN sync
			FILTER sync.endpoint_name == @endpoint_name
			COLLECT release_name = sync.release_name INTO syncGroups = sync
			LET latestSync = (
				FOR s IN syncGroups
					SORT DATE_TIMESTAMP(s.sync.synced_at) DESC
					LIMIT 1
					RETURN s.sync
			)[0]
			RETURN {
				name: latestSync.release_name,
				version: latestSync.release_version
			}
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"endpoint_name": endpointName},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	currentReleases := make(map[string]string)
	for cursor.HasMore() {
		var rel struct{ Name, Version string }
		if _, err := cursor.ReadDocument(ctx, &rel); err == nil {
			currentReleases[rel.Name] = rel.Version
		}
	}
	return currentReleases, nil
}

func isVersionGreater(newRel, existingRel model.ProjectRelease) bool {
	getVal := func(ptr *int) int {
		if ptr == nil {
			return 0
		}
		return *ptr
	}
	if getVal(newRel.VersionMajor) != getVal(existingRel.VersionMajor) {
		return getVal(newRel.VersionMajor) > getVal(existingRel.VersionMajor)
	}
	if getVal(newRel.VersionMinor) != getVal(existingRel.VersionMinor) {
		return getVal(newRel.VersionMinor) > getVal(existingRel.VersionMinor)
	}
	if getVal(newRel.VersionPatch) != getVal(existingRel.VersionPatch) {
		return getVal(newRel.VersionPatch) > getVal(existingRel.VersionPatch)
	}
	return newRel.VersionPrerelease > existingRel.VersionPrerelease
}

func processReleases(ctx context.Context, db database.DBConnection, req model.SyncWithEndpoint,
	currentReleases map[string]string) ([]ReleaseResult, map[string]string, error) {

	var results []ReleaseResult
	updatedReleases := make(map[string]string)
	latestInBatch := make(map[string]model.ProjectRelease)

	for name, version := range currentReleases {
		updatedReleases[name] = version
	}

	for _, relSync := range req.Releases {
		relSync.Release.Version = util.CleanVersion(relSync.Release.Version)
		relSync.Release.ParseAndSetVersion()

		result := processRelease(ctx, db, relSync, currentReleases)
		results = append(results, result)

		if result.Status != "error" {
			if existing, exists := latestInBatch[relSync.Release.Name]; exists {
				if isVersionGreater(relSync.Release, existing) {
					latestInBatch[relSync.Release.Name] = relSync.Release
				}
			} else {
				latestInBatch[relSync.Release.Name] = relSync.Release
			}
		}
	}

	for name, release := range latestInBatch {
		updatedReleases[name] = release.Version
	}
	return results, updatedReleases, nil
}

func processRelease(ctx context.Context, db database.DBConnection, relSync model.ReleaseSync,
	currentReleases map[string]string) ReleaseResult {

	release := relSync.Release
	sbomData := relSync.SBOM

	if release.Name == "" || release.Version == "" {
		return ReleaseResult{Status: "error", Message: "Release name and version are required"}
	}

	cleanedVersion := util.CleanVersion(release.Version)
	release.Version = cleanedVersion
	release.ParseAndSetVersion()
	release.ParseAndSetNameComponents()
	if release.ObjType == "" {
		release.ObjType = "ProjectRelease"
	}
	releases.PopulateContentSha(&release)

	currentVersion, existsInCurrent := currentReleases[release.Name]
	if existsInCurrent && currentVersion == cleanedVersion && sbomData == nil {
		return ReleaseResult{Name: release.Name, Version: cleanedVersion, Status: "unchanged", Message: "Release already at this version"}
	}

	var existingReleaseKey string
	if release.ContentSha != "" {
		existingReleaseKey, _ = database.FindReleaseByCompositeKey(ctx, db.Database, release.Name, release.Version, release.ContentSha)
	}

	var releaseID string
	releaseCreated := false
	if existingReleaseKey != "" {
		releaseID = "release/" + existingReleaseKey
	} else {
		releaseMeta, err := db.Collections["release"].CreateDocument(ctx, release)
		if err != nil {
			return ReleaseResult{Status: "error", Message: err.Error()}
		}
		releaseID = "release/" + releaseMeta.Key
		releaseCreated = true
	}

	sbomProcessed := false
	if sbomData != nil && len(sbomData.Content) > 0 {
		sbomProcessed = processSBOMForRelease(ctx, db, sbomData, releaseID)
	}

	statusMsg := "updated"
	if releaseCreated && sbomProcessed {
		statusMsg = "created_with_sbom"
	} else if releaseCreated {
		statusMsg = "created"
	} else if sbomProcessed {
		statusMsg = "updated_with_sbom"
	}

	return ReleaseResult{Name: release.Name, Version: cleanedVersion, Status: statusMsg, Message: "Release processed successfully"}
}

func batchFindOrCreatePURLs(ctx context.Context, db database.DBConnection, purls []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, basePurl := range purls {
		purlKey := util.SanitizeKey(basePurl)
		purlNode := map[string]interface{}{"_key": purlKey, "purl": basePurl, "objtype": "PURL"}
		db.Collections["purl"].CreateDocument(ctx, purlNode)
		result[basePurl] = "purl/" + purlKey
	}
	return result, nil
}

func processSBOMComponentsWithFixedPURLs(ctx context.Context, db database.DBConnection, sbomData model.SBOM, sbomID string) error {
	var sbomContent map[string]interface{}
	json.Unmarshal(sbomData.Content, &sbomContent)
	components, _ := sbomContent["components"].([]interface{})

	var basePurls []string
	var componentData []map[string]interface{}

	for _, comp := range components {
		compMap, _ := comp.(map[string]interface{})
		purl, _ := compMap["purl"].(string)
		cleaned, _ := util.CleanPURL(purl)
		basePurl, _ := util.GetBasePURL(cleaned)
		componentData = append(componentData, map[string]interface{}{"basePurl": basePurl, "fullPurl": cleaned, "version": compMap["version"]})
		basePurls = append(basePurls, basePurl)
	}

	purlMap, _ := batchFindOrCreatePURLs(ctx, db, basePurls)
	for _, data := range componentData {
		basePurl := data["basePurl"].(string)
		purlDocID, exists := purlMap[basePurl]
		if !exists {
			continue
		}
		versionStr, _ := data["version"].(string)
		parsed := util.ParseSemanticVersion(versionStr)
		edge := map[string]interface{}{"_from": sbomID, "_to": purlDocID, "version": versionStr, "full_purl": data["fullPurl"]}
		if parsed.Major != nil {
			edge["version_major"] = *parsed.Major
		}
		if parsed.Minor != nil {
			edge["version_minor"] = *parsed.Minor
		}
		if parsed.Patch != nil {
			edge["version_patch"] = *parsed.Patch
		}
		db.Collections["sbom2purl"].CreateDocument(ctx, edge)
	}
	return nil
}

func linkReleaseToExistingCVEs(ctx context.Context, db database.DBConnection, releaseID, releaseKey string) error {
	query := `
		FOR r IN release
			FILTER r._key == @releaseKey
			FOR sbom IN 1..1 OUTBOUND r release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					LET purl = DOCUMENT(sbomEdge._to)
					FILTER purl != null
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						LET cve = DOCUMENT(cveEdge._from)
						FILTER cve != null
						RETURN { cve_id: cve._id, package_purl: sbomEdge.full_purl, package_version: sbomEdge.version, all_affected: cve.affected }
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"releaseKey": releaseKey}})
	if err != nil {
		return err
	}
	defer cursor.Close()

	var edges []map[string]interface{}
	for cursor.HasMore() {
		var cand struct {
			CveID, PackagePurl, PackageVersion string
			AllAffected                        []models.Affected
		}
		cursor.ReadDocument(ctx, &cand)
		if util.IsVersionAffectedAny(cand.PackageVersion, cand.AllAffected) {
			edges = append(edges, map[string]interface{}{"_from": releaseID, "_to": cand.CveID, "type": "static_analysis", "package_purl": cand.PackagePurl, "package_version": cand.PackageVersion, "created_at": time.Now()})
		}
	}
	if len(edges) > 0 {
		return sbom.BatchInsertEdges(ctx, db, "release2cve", edges)
	}
	return nil
}

func processSBOMForRelease(ctx context.Context, db database.DBConnection, sbomData *model.SBOM, releaseID string) bool {
	if sbomData.ObjType == "" {
		sbomData.ObjType = "SBOM"
	}
	_, sbomID, err := sbom.ProcessSBOM(ctx, db, *sbomData)
	if err != nil {
		return false
	}
	releases.DeleteRelease2SBOMEdges(ctx, db, releaseID)
	edge := map[string]interface{}{"_from": releaseID, "_to": sbomID}
	db.Collections["release2sbom"].CreateDocument(ctx, edge)
	processSBOMComponentsWithFixedPURLs(ctx, db, *sbomData, sbomID)
	linkReleaseToExistingCVEs(ctx, db, releaseID, releaseID[8:])
	return true
}

func createSyncRecords(ctx context.Context, db database.DBConnection, endpointName string,
	updatedReleases map[string]string, syncedAt time.Time, results []ReleaseResult) (int, error) {
	count := 0
	for name, version := range updatedReleases {
		meta, err := fetchReleaseMetadata(ctx, db, name, version)
		if err != nil {
			continue
		}
		syncDoc := buildSyncDocument(meta, endpointName, syncedAt)
		syncMeta, err := db.Collections["sync"].CreateDocument(ctx, syncDoc)
		if err != nil {
			updateResultError(results, name, version, err)
			continue
		}
		count++
		updateResultSyncKey(results, name, version, syncMeta.Key)
	}
	return count, nil
}

func fetchReleaseMetadata(ctx context.Context, db database.DBConnection, name, version string) (*ReleaseMetadata, error) {
	query := `FOR r IN release FILTER r.name == @name && r.version == @version LIMIT 1 RETURN r`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"name": name, "version": version}})
	if err != nil || !cursor.HasMore() {
		return nil, fmt.Errorf("not found")
	}
	defer cursor.Close()
	var meta ReleaseMetadata
	cursor.ReadDocument(ctx, &meta)
	return &meta, nil
}

func buildSyncDocument(relMeta *ReleaseMetadata, endpointName string, syncedAt time.Time) map[string]interface{} {
	sync := map[string]interface{}{"release_name": relMeta.Name, "release_version": relMeta.Version, "endpoint_name": endpointName, "synced_at": syncedAt, "objtype": "Sync"}
	if relMeta.VersionMajor != nil {
		sync["release_version_major"] = *relMeta.VersionMajor
	}
	if relMeta.VersionMinor != nil {
		sync["release_version_minor"] = *relMeta.VersionMinor
	}
	if relMeta.VersionPatch != nil {
		sync["release_version_patch"] = *relMeta.VersionPatch
	}
	return sync
}

func updateResultError(results []ReleaseResult, name, version string, err error) {
	for i := range results {
		if results[i].Name == name && results[i].Version == version {
			results[i].Status = "error"
			results[i].Message = err.Error()
		}
	}
}

func updateResultSyncKey(results []ReleaseResult, name, version, syncKey string) {
	for i := range results {
		if results[i].Name == name && results[i].Version == version && results[i].Status != "unchanged" {
			results[i].SyncKey = syncKey
		}
	}
}

func buildSyncResponse(c *fiber.Ctx, results []ReleaseResult, syncedCount int, endpointExists bool,
	endpointName string, syncedAt time.Time) error {
	counts := countResults(results)
	message := buildResponseMessage(counts, syncedCount, endpointName, endpointExists)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"success": syncedCount > 0, "message": message, "synced_at": syncedAt, "results": results})
}

func countResults(results []ReleaseResult) map[string]int {
	counts := map[string]int{"created": 0, "created_with_sbom": 0, "updated": 0, "updated_with_sbom": 0, "unchanged": 0, "errors": 0}
	for _, result := range results {
		switch result.Status {
		case "created":
			counts["created"]++
		case "created_with_sbom":
			counts["created_with_sbom"]++
		case "updated":
			counts["updated"]++
		case "updated_with_sbom":
			counts["updated_with_sbom"]++
		case "unchanged":
			counts["unchanged"]++
		case "error":
			counts["errors"]++
		}
	}
	return counts
}

func buildResponseMessage(_ map[string]int, syncedCount int, endpointName string, endpointExists bool) string {
	msg := fmt.Sprintf("Created sync snapshot with %d releases for endpoint %s", syncedCount, endpointName)
	if !endpointExists {
		msg += " (endpoint created)"
	}
	return msg
}
