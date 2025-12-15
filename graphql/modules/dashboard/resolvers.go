// Package dashboard implements the resolvers for dashboard metrics.
package dashboard

import (
	"context"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/pdvd-backend/v12/database"
)

// ResolveOverview handles fetching the high-level dashboard metrics
func ResolveOverview(_ database.DBConnection) (interface{}, error) {
	// Placeholder - replaced by real calculations in MTTR query usually,
	// but kept here for compatibility with schema
	return map[string]interface{}{
		"total_releases":  0,
		"total_endpoints": 0,
		"total_cves":      0,
	}, nil
}

// ResolveSeverityDistribution fetches current breakdown of issues
func ResolveSeverityDistribution(_ database.DBConnection) (interface{}, error) {
	return map[string]interface{}{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}, nil
}

// ResolveTopRisks fetches the top risky assets based on type
func ResolveTopRisks(_ database.DBConnection, _ string, _ int) (interface{}, error) {
	// Placeholder logic
	var risks []map[string]interface{}
	return risks, nil
}

// ResolveVulnerabilityTrend returns daily counts of ALL open vulnerabilities
// Uses cve_lifecycle to reconstruct the state for each day in the window.
func ResolveVulnerabilityTrend(db database.DBConnection, days int) ([]map[string]interface{}, error) {
	ctx := context.Background()
	if days <= 0 {
		days = 180
	}

	// Define window
	now := time.Now().UTC()
	// Start date is 'days' ago, set to beginning of that day
	startDate := now.AddDate(0, 0, -days).Truncate(24 * time.Hour)

	// Fetch relevant lifecycle events:
	// 1. Introduced before or during the window
	// 2. Not remediated OR Remediated after the start of the window
	query := `
		FOR r IN cve_lifecycle
			FILTER r.introduced_at <= @now
			FILTER r.is_remediated == false OR r.remediated_at >= @startDate
			RETURN {
				severity: r.severity_rating,
				introduced_at: r.introduced_at,
				remediated_at: r.remediated_at,
				is_remediated: r.is_remediated
			}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"now":       now,
			"startDate": startDate,
		},
	})
	if err != nil {
		return []map[string]interface{}{}, err
	}
	defer cursor.Close()

	// Struct to hold event data
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

	// Build the timeline in Go
	var trendData []map[string]interface{}

	// Iterate through each day from startDate to now
	for d := 0; d <= days; d++ {
		currentDate := startDate.AddDate(0, 0, d)
		// End of this specific day for comparison
		endOfDay := currentDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)

		counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}

		for _, evt := range events {
			// Was the vulnerability active on this day?
			// Active if:
			// 1. Introduced on or before this day
			// 2. Not yet remediated OR Remediated after this day

			introduced := evt.IntroducedAt.Before(endOfDay)

			stillActive := true
			if evt.IsRemediated && evt.RemediatedAt != nil {
				// If remediated before or on this day, it's not active anymore
				if evt.RemediatedAt.Before(endOfDay) {
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
func ResolveDashboardGlobalStatus(_ database.DBConnection, _ int) (map[string]interface{}, error) {
	// Placeholder - matches simple response for now
	return map[string]interface{}{
		"critical":    map[string]int{"count": 0, "delta": 0},
		"high":        map[string]int{"count": 0, "delta": 0},
		"medium":      map[string]int{"count": 0, "delta": 0},
		"low":         map[string]int{"count": 0, "delta": 0},
		"total_count": 0,
		"total_delta": 0,
	}, nil
}

// ============================================================================
// MTTR & Metrics Resolvers
// ============================================================================

// ResolveMTTR calculates comprehensive metrics defined in the Dashboard Layout
func ResolveMTTR(db database.DBConnection, days int) (map[string]interface{}, error) {
	ctx := context.Background()
	// Default to 180 days if not specified
	if days <= 0 {
		days = 180
	}
	cutoffDate := time.Now().AddDate(0, 0, -days)

	// AQL Query to calculate Remediation, Exposure, SLA, Flow, and Endpoint metrics
	query := `
		// SLA Definitions per Section 1
		LET sla_def = { 
			"CRITICAL": { "default": 15, "high_risk": 7 }, 
			"HIGH":     { "default": 30, "high_risk": 15 }, 
			"MEDIUM":   { "default": 90, "high_risk": 90 }, 
			"LOW":      { "default": 180, "high_risk": 180 },
			"NONE":     { "default": 365, "high_risk": 365 }
		}

		// 1. Fetch Endpoint Types for SLA and Impact Analysis
		LET endpoint_types = (
			FOR e IN endpoint 
			RETURN { name: e.name, type: e.endpoint_type }
		)
		// Convert to object for fast lookup: { "endpoint_name": "type" }
		LET ep_map = MERGE(
			FOR item IN endpoint_types 
			RETURN { [item.name]: item.type }
		)

		// 2. Analyzed Lifecycle Events
		LET events = (
			FOR r IN cve_lifecycle
				LET ep_type = HAS(ep_map, r.endpoint_name) ? ep_map[r.endpoint_name] : "unknown"
				// Check if "High-Risk"
				LET is_high_risk = (ep_type == "mission_asset")
				
				// Determine SLA Days
				LET sev_key = UPPER(r.severity_rating)
				LET sla_entry = HAS(sla_def, sev_key) ? sla_def[sev_key] : sla_def["NONE"]
				LET sla_days = is_high_risk ? sla_entry.high_risk : sla_entry.default
				
				// Calculate age for open items
				LET open_age = r.is_remediated ? 0 : DATE_DIFF(r.introduced_at, DATE_NOW(), "d")
				
				RETURN MERGE(r, {
					endpoint_type: ep_type,
					sla_days: sla_days,
					open_age: open_age,
					// Check if detection/fix happened in the rolling window
					in_window_fix: (r.is_remediated AND r.remediated_at >= @cutoffDate),
					in_window_detect: (r.introduced_at >= @cutoffDate),
					// Post-Deployment flag
					is_post_deploy: r.disclosed_after_deployment == true
				})
		)

		// 3. Aggregate by Severity (Sections A, B, C, D)
		LET severity_groups = (
			FOR e IN events
				COLLECT severity = e.severity_rating INTO groups = e
				
				// --- A. Remediation Effectiveness (Closed CVEs) ---
				LET fixed_in_window = (FOR g IN groups FILTER g.in_window_fix RETURN g)
				LET count_fixed = LENGTH(fixed_in_window)
				
				LET sum_mttr = SUM(fixed_in_window[*].days_to_remediate)
				LET mttr = count_fixed > 0 ? sum_mttr / count_fixed : 0

				// A.3 MTTR Post-Deployment Only
				LET fixed_post = (FOR g IN groups FILTER g.in_window_fix AND g.is_post_deploy RETURN g)
				LET count_fixed_post = LENGTH(fixed_post)
				LET mttr_post = count_fixed_post > 0 ? SUM(fixed_post[*].days_to_remediate) / count_fixed_post : 0

				// C.2 % Fixed Within SLA
				LET fixed_within_sla = LENGTH(FOR g IN groups FILTER g.in_window_fix AND g.days_to_remediate <= g.sla_days RETURN 1)
				LET pct_fixed_sla = count_fixed > 0 ? (fixed_within_sla / count_fixed) * 100 : 0

				// --- B. Active Risk Exposure (Open CVEs) ---
				LET open_items = (FOR g IN groups FILTER g.is_remediated == false RETURN g)
				LET count_open = LENGTH(open_items)
				
				LET mean_age = count_open > 0 ? AVG(open_items[*].open_age) : 0
				LET oldest_days = count_open > 0 ? MAX(open_items[*].open_age) : 0

				// B.3 Mean Open Age – Post-Deployment
				LET open_post = (FOR g IN groups FILTER g.is_remediated == false AND g.is_post_deploy RETURN g)
				LET count_open_post = LENGTH(open_post)
				LET mean_age_post = count_open_post > 0 ? AVG(open_post[*].open_age) : 0

				// C.1 % Open Endpoint CVEs Beyond SLA
				LET open_beyond_sla = LENGTH(FOR g IN groups FILTER g.is_remediated == false AND g.open_age > g.sla_days RETURN 1)
				LET pct_open_sla = count_open > 0 ? (open_beyond_sla / count_open) * 100 : 0

				// --- D. Volume & Flow Metrics ---
				LET new_detected = LENGTH(FOR g IN groups FILTER g.in_window_detect RETURN 1)
				
				RETURN {
					severity: severity,
					mttr: mttr,
					mttr_post_deployment: mttr_post,
					fixed_within_sla_pct: pct_fixed_sla,
					backlog_count: count_open,
					open_count: count_open,
					mean_open_age: mean_age,
					mean_open_age_post_deploy: mean_age_post,
					oldest_open_days: oldest_days,
					open_beyond_sla_pct: pct_open_sla,
					open_beyond_sla_count: open_beyond_sla,
					new_detected: new_detected,
					remediated: count_fixed,
					// Helpers for aggregation
					open_post_count: count_open_post
				}
		)

		// 4. Endpoint Impact Metrics (Section E)
		// E.1 Affected Endpoints (Open CVEs)
		LET unique_affected_endpoints = LENGTH(UNIQUE(
			FOR e IN events 
			FILTER e.is_remediated == false 
			RETURN e.endpoint_name
		))

		// E.2 Post-Deployment CVEs by Endpoint Type
		LET post_deploy_open = (
			FOR e IN events
			FILTER e.is_remediated == false AND e.is_post_deploy == true
			RETURN e
		)
		
		LET post_deploy_by_type = (
			FOR e IN post_deploy_open
				COLLECT type = e.endpoint_type WITH COUNT INTO count
				RETURN { type: type, count: count }
		)

		// 5. Executive Summary Aggregation (Section G)
		LET total_fixed = SUM(severity_groups[*].remediated)
		
		LET exec_summary = {
			total_new_cves: SUM(severity_groups[*].new_detected),
			total_fixed_cves: total_fixed,
			post_deployment_cves: SUM(severity_groups[*].open_post_count),
			
			// Averages across severity groups
			mttr_all: LENGTH(severity_groups) > 0 ? AVG(severity_groups[*].mttr) : 0,
			mttr_post_deployment: LENGTH(severity_groups) > 0 ? AVG(severity_groups[*].mttr_post_deployment) : 0,
			
			mean_open_age_all: LENGTH(severity_groups) > 0 ? AVG(severity_groups[*].mean_open_age) : 0,
			mean_open_age_post_deploy: LENGTH(severity_groups) > 0 ? AVG(severity_groups[*].mean_open_age_post_deploy) : 0,
			
			// Global % Open Beyond SLA
			open_cves_beyond_sla_pct: SUM(severity_groups[*].backlog_count) > 0 ? 
				(SUM(severity_groups[*].open_beyond_sla_count) / SUM(severity_groups[*].backlog_count)) * 100 : 0,

			// Global % Fixed Within SLA
			fixed_within_sla_pct: total_fixed > 0 ? AVG(severity_groups[*].fixed_within_sla_pct) : 0,

			// B.4 Oldest Open Critical
			oldest_open_critical_days: MAX(
				FOR g IN severity_groups 
				FILTER g.severity == "CRITICAL" 
				RETURN g.oldest_open_days
			),
			
			// D.3 Backlog Delta
			backlog_delta: SUM(severity_groups[*].new_detected) - SUM(severity_groups[*].remediated)
		}

		RETURN {
			by_severity: severity_groups,
			executive_summary: exec_summary,
			endpoint_impact: {
				affected_endpoints_count: unique_affected_endpoints,
				post_deployment_cves_by_type: post_deploy_by_type
			}
		}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cutoffDate": cutoffDate,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	// Structs to decode AQL Result
	type ExecSummary struct {
		TotalNew               int     `json:"total_new_cves"`
		TotalFixed             int     `json:"total_fixed_cves"`
		PostDeploymentCount    int     `json:"post_deployment_cves"`
		MTTRAll                float64 `json:"mttr_all"`
		MTTRPost               float64 `json:"mttr_post_deployment"`
		MeanOpenAge            float64 `json:"mean_open_age_all"`
		MeanOpenAgePost        float64 `json:"mean_open_age_post_deploy"`
		OpenBeyondSLAPct       float64 `json:"open_cves_beyond_sla_pct"`
		FixedWithinSLAPct      float64 `json:"fixed_within_sla_pct"`
		OldestOpenCriticalDays float64 `json:"oldest_open_critical_days"`
		BacklogDelta           int     `json:"backlog_delta"`
	}

	type SeverityRow struct {
		Severity           string  `json:"severity"`
		MTTR               float64 `json:"mttr"`
		MTTRPost           float64 `json:"mttr_post_deployment"`
		FixedWithinSLAPct  float64 `json:"fixed_within_sla_pct"`
		BacklogCount       int     `json:"backlog_count"`
		OpenCount          int     `json:"open_count"`
		MeanOpenAge        float64 `json:"mean_open_age"`
		MeanOpenAgePost    float64 `json:"mean_open_age_post_deploy"`
		OldestOpenDays     float64 `json:"oldest_open_days"`
		OpenBeyondSLAPct   float64 `json:"open_beyond_sla_pct"`
		OpenBeyondSLACount int     `json:"open_beyond_sla_count"`
		NewDetected        int     `json:"new_detected"`
		Remediated         int     `json:"remediated"`
	}

	type ImpactCount struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}

	type ImpactMetrics struct {
		AffectedCount  int           `json:"affected_endpoints_count"`
		PostDeployType []ImpactCount `json:"post_deployment_cves_by_type"`
	}

	type DBResult struct {
		BySeverity       []SeverityRow `json:"by_severity"`
		ExecutiveSummary ExecSummary   `json:"executive_summary"`
		EndpointImpact   ImpactMetrics `json:"endpoint_impact"`
	}

	var data DBResult
	if cursor.HasMore() {
		_, err := cursor.ReadDocument(ctx, &data)
		if err != nil {
			return nil, err
		}
	}

	// Sort Severity Rows for UI consistency
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	sevMap := make(map[string]SeverityRow)
	for _, row := range data.BySeverity {
		sevMap[row.Severity] = row
	}

	var orderedRows []SeverityRow
	for _, sev := range order {
		if row, ok := sevMap[sev]; ok {
			orderedRows = append(orderedRows, row)
		} else {
			orderedRows = append(orderedRows, SeverityRow{Severity: sev})
		}
	}
	// Add remaining
	for _, row := range data.BySeverity {
		found := false
		for _, o := range order {
			if row.Severity == o {
				found = true
				break
			}
		}
		if !found {
			orderedRows = append(orderedRows, row)
		}
	}

	return map[string]interface{}{
		"executive_summary": data.ExecutiveSummary,
		"by_severity":       orderedRows,
		"endpoint_impact":   data.EndpointImpact,
	}, nil
}
