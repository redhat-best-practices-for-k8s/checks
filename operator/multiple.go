package operator

import (
	"fmt"
	"strings"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckMultipleSameOperators verifies that no operator is installed more than once
// in the cluster (by comparing CSV base names after stripping version suffixes).
func CheckMultipleSameOperators(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.CSVs) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No operators (CSVs) found"
		return result
	}

	// Build map of base name -> list of CSV names
	type csvInfo struct {
		name      string
		namespace string
		version   string
	}
	baseNameMap := make(map[string][]csvInfo)

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		version := csv.Spec.Version.String()
		baseName := csv.Name
		if version != "" {
			baseName = strings.TrimSuffix(baseName, ".v"+version)
		}
		baseNameMap[baseName] = append(baseNameMap[baseName], csvInfo{
			name:      csv.Name,
			namespace: csv.Namespace,
			version:   version,
		})
	}

	var nonCompliant int
	for baseName, csvs := range baseNameMap {
		if len(csvs) <= 1 {
			for _, csv := range csvs {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "ClusterServiceVersion",
					Name:      csv.name,
					Namespace: csv.namespace,
					Compliant: true,
					Message:   fmt.Sprintf("Operator %q installed once (version %s)", baseName, csv.version),
				})
			}
			continue
		}
		nonCompliant++
		for _, csv := range csvs {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "ClusterServiceVersion",
				Name:      csv.name,
				Namespace: csv.namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Operator %q installed multiple times (version %s)", baseName, csv.version),
			})
		}
	}

	if nonCompliant > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d operator(s) installed more than once", nonCompliant)
	}
	return result
}
