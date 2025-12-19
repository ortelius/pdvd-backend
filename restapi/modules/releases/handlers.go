// Package releases implements the REST API handlers for release operations.
package releases

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
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/sbom"
	"github.com/ortelius/pdvd-backend/v12/util"
)

// PostReleaseWithSBOM handles POST requests for creating a release with its SBOM
func PostReleaseWithSBOM(db database.DBConnection) fiber.Handler {
	return func(c *fiber.Ctx) error {
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

		// Parse and set name components
		req.ParseAndSetNameComponents()

		ctx := context.Background()

		// Populate ContentSha based on project type
		PopulateContentSha(&req.ProjectRelease)

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

		// Process SBOM
		existingSBOMKey, sbomID, err := sbom.ProcessSBOM(ctx, db, req.SBOM)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
				Success: false,
				Message: "Failed to process SBOM: " + err.Error(),
			})
		}

		// Delete any existing release2sbom edges for this release
		err = DeleteRelease2SBOMEdges(ctx, db, releaseID)
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
		err = sbom.ProcessSBOMComponents(ctx, db, req.SBOM, sbomID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
				Success: false,
				Message: "Failed to process SBOM components: " + err.Error(),
			})
		}

		// Link Release directly to CVEs (Materialized Edges)
		if err := deleteRelease2CVEEdges(ctx, db, releaseID); err != nil {
			fmt.Printf("Warning: Failed to cleanup old CVE edges: %v\n", err)
		}

		if err := linkReleaseToExistingCVEs(ctx, db, releaseID, req.Key); err != nil {
			fmt.Printf("Error linking release to CVEs: %v\n", err)
		}

		// Determine success message
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

		return c.Status(fiber.StatusCreated).JSON(ReleaseWithSBOMResponse{
			Success: true,
			Message: message,
		})
	}
}

// PopulateContentSha sets the ContentSha field based on project type
func PopulateContentSha(release *model.ProjectRelease) {
	if release.ProjectType == "docker" || release.ProjectType == "container" {
		if release.DockerSha != "" {
			release.ContentSha = release.DockerSha
		} else if release.GitCommit != "" {
			release.ContentSha = release.GitCommit
		}
	} else {
		if release.GitCommit != "" {
			release.ContentSha = release.GitCommit
		} else if release.DockerSha != "" {
			release.ContentSha = release.DockerSha
		}
	}
}

// DeleteRelease2SBOMEdges deletes all existing release2sbom edges for a given release
func DeleteRelease2SBOMEdges(ctx context.Context, db database.DBConnection, releaseID string) error {
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

// deleteRelease2CVEEdges deletes all existing release2cve edges for a given release
func deleteRelease2CVEEdges(ctx context.Context, db database.DBConnection, releaseID string) error {
	query := `
		FOR e IN release2cve
			FILTER e._from == @releaseID
			REMOVE e IN release2cve
	`
	bindVars := map[string]interface{}{
		"releaseID": releaseID,
	}

	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	return err
}

// linkReleaseToExistingCVEs finds matching CVEs for a release and creates materialized edges
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
						
						FILTER (
							sbomEdge.version_major != null AND 
							cveEdge.introduced_major != null AND 
							cveEdge.introduced_major > 0 AND 
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
							cve_doc_id: cve.id,
							package_purl: sbomEdge.full_purl,
							package_version: sbomEdge.version,
							all_affected: matchedAffected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"releaseKey": releaseKey,
		},
	})
	if err != nil {
		return err
	}
	defer cursor.Close()

	var edgesToInsert []map[string]interface{}

	type Candidate struct {
		CveID           string            `json:"cve_id"`
		CveDocID        string            `json:"cve_doc_id"`
		PackagePurl     string            `json:"package_purl"`
		PackageVersion  string            `json:"package_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	seenInstances := make(map[string]bool)

	for cursor.HasMore() {
		var cand Candidate
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			continue
		}

		instanceKey := cand.CveID + ":" + cand.PackagePurl
		if seenInstances[instanceKey] {
			continue
		}

		if cand.NeedsValidation {
			isAffected := false
			for _, affected := range cand.AllAffected {
				if util.IsVersionAffected(cand.PackageVersion, affected) {
					isAffected = true
					break
				}
			}
			if !isAffected {
				continue
			}
		}

		seenInstances[instanceKey] = true

		edgesToInsert = append(edgesToInsert, map[string]interface{}{
			"_from":           releaseID,
			"_to":             cand.CveID,
			"type":            "static_analysis",
			"package_purl":    cand.PackagePurl,
			"package_version": cand.PackageVersion,
			"created_at":      time.Now(),
		})
	}

	if len(edgesToInsert) > 0 {
		return sbom.BatchInsertEdges(ctx, db, "release2cve", edgesToInsert)
	}

	return nil
}
