// Package lifecycle provides CVE lifecycle event tracking and management.
package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/util"
)

// CreateOrUpdateLifecycleRecord creates a new lifecycle record or updates existing one.
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

	// PERMANENT FIX: Block zero-value timestamps from polluting the collection [cite: 19]
	if introducedAt.IsZero() {
		return fmt.Errorf("refusing to create lifecycle record with zero-value timestamp for %s", cveInfo.CVEID)
	}

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
		return fmt.Errorf("failed to check record: %w", err)
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var existing map[string]interface{}
		cursor.ReadDocument(ctx, &existing)
		updateQuery := `UPDATE @key WITH { updated_at: DATE_NOW(), disclosed_after_deployment: OLD.disclosed_after_deployment || @disclosed_after } IN cve_lifecycle`
		_, err = db.Database.Query(ctx, updateQuery, &arangodb.QueryOptions{BindVars: map[string]interface{}{"key": existing["_key"], "disclosed_after": disclosedAfter}})
		return err
	}

	isDisclosedAfter := !cveInfo.Published.IsZero() && cveInfo.Published.After(introducedAt)

	record := map[string]interface{}{
		"cve_id": cveInfo.CVEID, "endpoint_name": endpointName, "release_name": releaseName, "package": cveInfo.Package,
		"severity_rating": cveInfo.SeverityRating, "severity_score": cveInfo.SeverityScore, "introduced_at": introducedAt,
		"introduced_version": releaseVersion, "remediated_at": nil, "remediated_version": nil, "days_to_remediate": nil,
		"is_remediated": false, "disclosed_after_deployment": isDisclosedAfter, "published": cveInfo.Published,
		"objtype": "CVELifecycleEvent", "created_at": time.Now().UTC(), "updated_at": time.Now().UTC(),
	}

	_, err = db.Collections["cve_lifecycle"].CreateDocument(ctx, record)
	return err
}

func MarkCVERemediated(ctx context.Context, db database.DBConnection, endpointName, releaseName, prevVersion, currentVersion, cveID, pkgPURL string, remediatedAt time.Time) error {
	query := `
		FOR r IN cve_lifecycle
			FILTER r.cve_id == @cve_id AND r.package == @package AND r.release_name == @release_name AND r.endpoint_name == @endpoint_name AND r.introduced_version == @prev_version AND r.is_remediated == false
			LIMIT 1
			UPDATE r WITH { is_remediated: true, remediated_at: @remediated_at, remediated_version: @current_version, days_to_remediate: DATE_DIFF(DATE_TIMESTAMP(r.introduced_at), @rem_ts, "d"), updated_at: DATE_NOW() } IN cve_lifecycle
	`
	_, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"cve_id": cveID, "package": pkgPURL, "release_name": releaseName, "endpoint_name": endpointName, "prev_version": prevVersion, "current_version": currentVersion, "remediated_at": remediatedAt, "rem_ts": remediatedAt.Unix() * 1000},
	})
	return err
}

func CompareAndMarkRemediations(ctx context.Context, db database.DBConnection, endpointName, releaseName, prevVersion, currentVersion string, currentCVEs map[string]CVEInfo, remediatedAt time.Time) (int, error) {
	query := `FOR r IN cve_lifecycle FILTER r.release_name == @release_name AND r.endpoint_name == @endpoint_name AND r.introduced_version == @prev_version AND r.is_remediated == false RETURN { cve_id: r.cve_id, package: r.package, key: CONCAT(r.cve_id, ":", r.package) }`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"release_name": releaseName, "endpoint_name": endpointName, "prev_version": prevVersion}})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	count := 0
	for cursor.HasMore() {
		var prev struct{ CVEID, Package, Key string }
		if _, err := cursor.ReadDocument(ctx, &prev); err == nil {
			if _, exists := currentCVEs[prev.Key]; !exists {
				MarkCVERemediated(ctx, db, endpointName, releaseName, prevVersion, currentVersion, prev.CVEID, prev.Package, remediatedAt)
				count++
			}
		}
	}
	return count, nil
}

func GetPreviousVersion(ctx context.Context, db database.DBConnection, releaseName, endpointName string, currentSyncTime time.Time) (string, error) {
	// Robust Sorting Fix [cite: 13, 19]
	query := `FOR s IN sync FILTER s.release_name == @release_name AND s.endpoint_name == @endpoint_name AND DATE_TIMESTAMP(s.synced_at) < @current_time SORT DATE_TIMESTAMP(s.synced_at) DESC LIMIT 1 RETURN s.release_version`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"release_name": releaseName, "endpoint_name": endpointName, "current_time": currentSyncTime.Unix() * 1000}})
	if err != nil || !cursor.HasMore() {
		return "", err
	}
	defer cursor.Close()
	var version string
	cursor.ReadDocument(ctx, &version)
	return version, nil
}

func GetSyncTimestamp(ctx context.Context, db database.DBConnection, releaseName, releaseVersion, endpointName string) (time.Time, error) {
	// Normalization Fix [cite: 13, 19]
	query := `FOR s IN sync FILTER s.release_name == @release_name AND s.release_version == @release_version AND s.endpoint_name == @endpoint_name SORT DATE_TIMESTAMP(s.synced_at) DESC LIMIT 1 RETURN DATE_ISO8601(s.synced_at)`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"release_name": releaseName, "release_version": releaseVersion, "endpoint_name": endpointName}})
	if err != nil || !cursor.HasMore() {
		return time.Time{}, fmt.Errorf("not found")
	}
	defer cursor.Close()
	var timestamp time.Time
	cursor.ReadDocument(ctx, &timestamp)
	return timestamp, nil
}

func GetCVEsForReleaseTracking(ctx context.Context, db database.DBConnection, releaseName, releaseVersion string) (map[string]CVEInfo, error) {
	// Normalization Fix [cite: 13, 19]
	query := `FOR r IN release FILTER r.name == @name AND r.version == @version LIMIT 1 FOR cve, edge IN 1..1 OUTBOUND r release2cve RETURN { cve_id: cve.id, package: edge.package_purl, severity_rating: cve.database_specific.severity_rating, severity_score: cve.database_specific.cvss_base_score, published: DATE_ISO8601(cve.published) }`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"name": releaseName, "version": releaseVersion}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	result := make(map[string]CVEInfo)
	for cursor.HasMore() {
		var raw struct {
			CveID, Package, SeverityRating, Published string
			SeverityScore                             float64
		}
		if _, err := cursor.ReadDocument(ctx, &raw); err == nil {
			pubTime, _ := time.Parse(time.RFC3339, raw.Published)
			result[raw.CveID] = CVEInfo{
				CVEID: raw.CveID, Package: raw.Package, SeverityRating: raw.SeverityRating, SeverityScore: raw.SeverityScore, Published: pubTime,
				// FIXED: Populate context fields
				ReleaseName: releaseName, ReleaseVersion: releaseVersion,
			}
		}
	}
	return result, nil
}

func CreateRelease2CVEEdges(ctx context.Context, db database.DBConnection, releaseID string) error {
	query := `LET release = DOCUMENT(@release_id) LET sbom = FIRST(FOR s IN 1..1 OUTBOUND release release2sbom LIMIT 1 RETURN s) FILTER sbom != null FOR sbomEdge IN sbom2purl FILTER sbomEdge._from == sbom._id LET purl = DOCUMENT(sbomEdge._to) FILTER purl != null FOR cveEdge IN cve2purl FILTER cveEdge._to == purl._id LET cve = DOCUMENT(cveEdge._from) FILTER cve != null RETURN { cve_id: cve._id, package_purl: purl.purl, package_version: sbomEdge.version, all_affected: cve.affected }`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"release_id": releaseID}})
	if err != nil {
		return err
	}
	defer cursor.Close()
	for cursor.HasMore() {
		var cand struct {
			CveID, PackagePurl, PackageVersion string
			AllAffected                        []models.Affected
		}
		if _, err := cursor.ReadDocument(ctx, &cand); err == nil && util.IsVersionAffectedAny(cand.PackageVersion, cand.AllAffected) {
			db.Collections["release2cve"].CreateDocument(ctx, map[string]interface{}{"_from": releaseID, "_to": cand.CveID, "type": "sbom_analysis", "package_purl": cand.PackagePurl, "package_version": cand.PackageVersion, "created_at": time.Now()})
		}
	}
	return nil
}

func BuildCVEMap(cves []CVEInfo) map[string]CVEInfo {
	res := make(map[string]CVEInfo)
	for _, c := range cves {
		res[fmt.Sprintf("%s:%s", c.CVEID, c.Package)] = c
	}
	return res
}
