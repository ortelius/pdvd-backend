// Package dashboard implements the resolvers for dashboard metrics.
// It provides GraphQL resolvers for vulnerability trend analysis, MTTR calculations,
// and dashboard overview statistics.
package dashboard

import (
	"context"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/pdvd-backend/v12/database"
)

// ResolveOverview handles fetching the high-level dashboard metrics
func ResolveOverview(db database.DBConnection) (interface{}, error) {
	ctx := context.Background()
	query := `
		RETURN {
			total_releases: LENGTH(release),
			total_endpoints: LENGTH(endpoint),
			total_cves: LENGTH(cve)
		}
	`
	cursor, err := db.Database.Query(ctx, query, nil)
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var result map[string]interface{}
	if cursor.HasMore() {
		_, err = cursor.ReadDocument(ctx, &result)
	}
	return result, err
}

// ResolveSeverityDistribution fetches current breakdown of issues
func ResolveSeverityDistribution(db database.DBConnection) (interface{}, error) {
	ctx := context.Background()
	query := `
		LET counts = (
			FOR r IN cve_lifecycle
				FILTER r.is_remediated == false
				COLLECT severity = r.severity_rating WITH COUNT INTO count
				RETURN { [LOWER(severity)]: count }
		)
		RETURN MERGE(counts)
	`
	cursor, err := db.Database.Query(ctx, query, nil)
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var result map[string]int
	if cursor.HasMore() {
		_, err = cursor.ReadDocument(ctx, &result)
	}
	return result, err
}

// ResolveTopRisks fetches the top risky assets based on type
func ResolveTopRisks(db database.DBConnection, assetType string, limit int) (interface{}, error) {
	ctx := context.Background()
	var query string

	if assetType == "releases" {
		query = `
			FOR r IN cve_lifecycle
				FILTER r.is_remediated == false
				COLLECT release = r.release_name, version = r.introduced_version AGGREGATE 
					critical = SUM(r.severity_rating == "CRITICAL" ? 1 : 0),
					high = SUM(r.severity_rating == "HIGH" ? 1 : 0),
					total = COUNT(r)
				SORT critical DESC, high DESC, total DESC
				LIMIT @limit
				RETURN {
					name: release,
					version: version,
					critical_count: critical,
					high_count: high,
					total_vulns: total
				}
		`
	} else {
		query = `
			FOR r IN cve_lifecycle
				FILTER r.is_remediated == false
				COLLECT endpoint = r.endpoint_name AGGREGATE 
					critical = SUM(r.severity_rating == "CRITICAL" ? 1 : 0),
					high = SUM(r.severity_rating == "HIGH" ? 1 : 0),
					total = COUNT(r)
				SORT critical DESC, high DESC, total DESC
				LIMIT @limit
				RETURN {
					name: endpoint,
					version: "-",
					critical_count: critical,
					high_count: high,
					total_vulns: total
				}
		`
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"limit": limit},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var risks []map[string]interface{}
	for cursor.HasMore() {
		var risk map[string]interface{}
		if _, err := cursor.ReadDocument(ctx, &risk); err == nil {
			risks = append(risks, risk)
		}
	}
	return risks, nil
}

// ResolveVulnerabilityTrend returns daily counts of ALL open vulnerabilities
func ResolveVulnerabilityTrend(db database.DBConnection, days int) ([]map[string]interface{}, error) {
	ctx := context.Background()
	if days <= 0 {
		days = 180
	}

	now := time.Now().UTC()
	startDate := now.AddDate(0, 0, -days).Truncate(24 * time.Hour)

	query := `
		FOR r IN cve_lifecycle
			LET introduced_ts = DATE_TIMESTAMP(r.introduced_at)
			LET remediated_ts = r.remediated_at != null ? DATE_TIMESTAMP(r.remediated_at) : null
			
			FILTER introduced_ts <= @now
			FILTER r.is_remediated == false OR remediated_ts >= @startDate
			RETURN {
				severity: r.severity_rating,
				introduced_at: DATE_ISO8601(introduced_ts),
				remediated_at: remediated_ts != null ? DATE_ISO8601(remediated_ts) : null,
				is_remediated: r.is_remediated
			}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"now":       now.Unix() * 1000,
			"startDate": startDate.Unix() * 1000,
		},
	})
	if err != nil {
		return []map[string]interface{}{}, err
	}
	defer cursor.Close()

	type LifecycleEvent struct {
		Severity     string     `json:"severity"`
		IntroducedAt time.Time  `json:"introduced_at"`
		RemediatedAt *time.Time `json:"remediated_at"`
		IsRemediated bool       `json:"is_remediated"`
	}

	var events []LifecycleEvent
	for cursor.HasMore() {
		var evt LifecycleEvent
		if _, err := cursor.ReadDocument(ctx, &evt); err == nil {
			events = append(events, evt)
		}
	}

	var trendData []map[string]interface{}
	for d := 0; d <= days; d++ {
		currentDate := startDate.AddDate(0, 0, d)
		endOfDay := currentDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)

		counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}

		for _, evt := range events {
			introduced := evt.IntroducedAt.Before(endOfDay) || evt.IntroducedAt.Equal(endOfDay)

			stillActive := true
			if evt.IsRemediated && evt.RemediatedAt != nil {
				if evt.RemediatedAt.Before(endOfDay) || evt.RemediatedAt.Equal(endOfDay) {
					stillActive = false
				}
			}

			if introduced && stillActive {
				sev := strings.ToLower(evt.Severity)
				if _, exists := counts[sev]; exists {
					counts[sev]++
				}
			}
		}

		trendData = append(trendData, map[string]interface{}{
			"date":     currentDate.Format("2006-01-02"),
			"critical": counts["critical"],
			"high":     counts["high"],
			"medium":   counts["medium"],
			"low":      counts["low"],
		})
	}

	return trendData, nil
}

// ResolveDashboardGlobalStatus calculates aggregated vulnerability counts and deltas
func ResolveDashboardGlobalStatus(db database.DBConnection, _ int) (map[string]interface{}, error) {
	ctx := context.Background()
	window := time.Now().AddDate(0, 0, -30).Unix() * 1000

	query := `
		LET stats = (
			FOR r IN cve_lifecycle
				LET introduced_ts = DATE_TIMESTAMP(r.introduced_at)
				LET remediated_ts = r.remediated_at != null ? DATE_TIMESTAMP(r.remediated_at) : null
				
				RETURN {
					severity: LOWER(r.severity_rating),
					is_open: (r.is_remediated == false),
					delta: (introduced_ts >= @window ? 1 : 0) - (r.is_remediated == true AND remediated_ts >= @window ? 1 : 0)
				}
		)

		LET results = (
			FOR s IN stats
				COLLECT severity = s.severity AGGREGATE 
					count = SUM(s.is_open ? 1 : 0),
					delta = SUM(s.delta)
				RETURN { severity: severity, count: count, delta: delta }
		)

		RETURN {
			critical: FIRST(FOR r IN results FILTER r.severity == "critical" RETURN { count: r.count, delta: r.delta }) || { count: 0, delta: 0 },
			high: FIRST(FOR r IN results FILTER r.severity == "high" RETURN { count: r.count, delta: r.delta }) || { count: 0, delta: 0 },
			medium: FIRST(FOR r IN results FILTER r.severity == "medium" RETURN { count: r.count, delta: r.delta }) || { count: 0, delta: 0 },
			low: FIRST(FOR r IN results FILTER r.severity == "low" RETURN { count: r.count, delta: r.delta }) || { count: 0, delta: 0 },
			total_count: SUM(results[*].count),
			total_delta: SUM(results[*].delta)
		}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"window": window},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var result map[string]interface{}
	if cursor.HasMore() {
		_, err = cursor.ReadDocument(ctx, &result)
	}
	return result, err
}

// ResolveMTTR calculates comprehensive metrics defined in the Dashboard Layout.
func ResolveMTTR(db database.DBConnection, days int) (map[string]interface{}, error) {
	ctx := context.Background()
	if days <= 0 {
		days = 180
	}
	cutoffDate := time.Now().AddDate(0, 0, -days)

	query := `
		LET sla_def = { 
			"CRITICAL": { "default": 15, "high_risk": 7 }, 
			"HIGH":     { "default": 30, "high_risk": 15 }, 
			"MEDIUM":   { "default": 90, "high_risk": 90 }, 
			"LOW":      { "default": 180, "high_risk": 180 },
			"NONE":     { "default": 365, "high_risk": 365 }
		}

		LET ep_map = MERGE(FOR e IN endpoint RETURN { [e.name]: e.endpoint_type })

		LET events = (
			FOR r IN cve_lifecycle
				LET introduced = DATE_TIMESTAMP(r.introduced_at)
				LET remediated = r.remediated_at != null ? DATE_TIMESTAMP(r.remediated_at) : null
				
				LET ep_type = HAS(ep_map, r.endpoint_name) ? ep_map[r.endpoint_name] : "unknown"
				LET is_high_risk = (ep_type == "mission_asset")
				
				LET sev_key = UPPER(r.severity_rating)
				LET sla_entry = HAS(sla_def, sev_key) ? sla_def[sev_key] : sla_def["NONE"]
				LET sla_days = is_high_risk ? sla_entry.high_risk : sla_entry.default
				
				RETURN MERGE(r, {
					endpoint_type: ep_type,
					sla_days: sla_days,
					open_age: r.is_remediated ? 0 : DATE_DIFF(introduced, DATE_NOW(), "d"),
					in_window_fix: (r.is_remediated AND remediated >= @cutoffDate),
					in_window_detect: (introduced >= @cutoffDate)
				})
		)

		LET severity_groups = (
			FOR e IN events
				COLLECT severity = e.severity_rating INTO groups = e
				
				LET fixed_in_window = (FOR g IN groups FILTER g.in_window_fix RETURN g)
				LET count_fixed = LENGTH(fixed_in_window)
				LET sum_mttr = SUM(fixed_in_window[*].days_to_remediate)

				LET fixed_post = (FOR g IN groups FILTER g.in_window_fix AND g.disclosed_after_deployment == true RETURN g)
				LET count_fixed_post = LENGTH(fixed_post)
				LET sum_mttr_post = SUM(fixed_post[*].days_to_remediate)

				LET fixed_within_sla = LENGTH(FOR g IN groups FILTER g.in_window_fix AND g.days_to_remediate <= g.sla_days RETURN 1)
				LET open_items = (FOR g IN groups FILTER g.is_remediated == false AND g.in_window_detect == true RETURN g)
				LET count_open = LENGTH(open_items)
				
				LET open_post = (FOR g IN groups FILTER g.in_window_detect == true AND g.is_remediated == false AND g.disclosed_after_deployment == true RETURN g)
				LET count_open_post = LENGTH(open_post)

				LET open_beyond_sla = LENGTH(FOR g IN groups FILTER g.is_remediated == false AND g.open_age > g.sla_days RETURN 1)
				
				RETURN {
					severity: severity,
					mttr: count_fixed > 0 ? sum_mttr / count_fixed : 0,
					mttr_post_deployment: count_fixed_post > 0 ? sum_mttr_post / count_fixed_post : 0,
					fixed_within_sla_pct: count_fixed > 0 ? (fixed_within_sla * 100.0 / count_fixed) : 0,
					open_count: count_open,
					backlog_count: count_open,
					mean_open_age: count_open > 0 ? AVG(open_items[*].open_age) : 0,
					mean_open_age_post_deploy: count_open_post > 0 ? AVG(open_post[*].open_age) : 0,
					oldest_open_days: count_open > 0 ? MAX(open_items[*].open_age) : 0,
					open_beyond_sla_pct: count_open > 0 ? (open_beyond_sla * 100.0 / count_open) : 0,
					open_beyond_sla_count: open_beyond_sla,
					new_detected: LENGTH(FOR g IN groups FILTER g.in_window_detect RETURN 1),
					remediated: count_fixed,
					open_post_count: count_open_post,
					
					// Hidden fields for weighted calculations
					_sum_mttr: sum_mttr || 0,
					_sum_mttr_post: sum_mttr_post || 0,
					_count_fixed_post: count_fixed_post,
					_sum_open_age: SUM(open_items[*].open_age) || 0,
					_sum_open_age_post: SUM(open_post[*].open_age) || 0,
					_count_fixed_within_sla: fixed_within_sla
				}
		)

		LET total_fixed = SUM(severity_groups[*].remediated)
		LET total_open = SUM(severity_groups[*].open_count)
		LET total_open_post = SUM(severity_groups[*].open_post_count)

		LET exec_summary = {
			total_new_cves: SUM(severity_groups[*].new_detected),
			total_fixed_cves: total_fixed,
			post_deployment_cves: total_open_post,
			
			mttr_all: total_fixed > 0 ? SUM(severity_groups[*]._sum_mttr) / total_fixed : 0,
			mttr_post_deployment: SUM(severity_groups[*]._count_fixed_post) > 0 ? SUM(severity_groups[*]._sum_mttr_post) / SUM(severity_groups[*]._count_fixed_post) : 0,
			
			mean_open_age_all: total_open > 0 ? SUM(severity_groups[*]._sum_open_age) / total_open : 0,
			mean_open_age_post_deploy: total_open_post > 0 ? SUM(severity_groups[*]._sum_open_age_post) / total_open_post : 0,
			
			open_cves_beyond_sla_pct: total_open > 0 ? (SUM(severity_groups[*].open_beyond_sla_count) * 100.0 / total_open) : 0,
			fixed_within_sla_pct: total_fixed > 0 ? (SUM(severity_groups[*]._count_fixed_within_sla) * 100.0 / total_fixed) : 0,

			oldest_open_critical_days: MAX(FOR g IN severity_groups FILTER g.severity == "CRITICAL" RETURN g.oldest_open_days),
			backlog_delta: SUM(severity_groups[*].new_detected) - total_fixed
		}

		RETURN {
			by_severity: severity_groups,
			executive_summary: exec_summary,
			endpoint_impact: {
				affected_endpoints_count: LENGTH(UNIQUE(FOR e IN events FILTER e.is_remediated == false RETURN e.endpoint_name)),
				post_deployment_cves_by_type: (FOR e IN events FILTER e.is_remediated == false AND e.disclosed_after_deployment == true COLLECT type = e.endpoint_type WITH COUNT INTO count RETURN { type: type, count: count })
			}
		}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"cutoffDate": cutoffDate.Unix() * 1000},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var data map[string]interface{}
	if cursor.HasMore() {
		_, err = cursor.ReadDocument(ctx, &data)
	}

	return data, err
}
