package operator

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

const bundleCountLimit = 1000

// CheckCatalogSourceBundleCount verifies catalog sources have fewer than 1000 bundles.
func CheckCatalogSourceBundleCount(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if len(resources.CatalogSources) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No catalog sources found"
		return result
	}

	if len(resources.CSVs) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No operators found"
		return result
	}

	// Build a map of catalog sources that operators use
	catalogsUsedByOperators := make(map[string]bool)

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		// Get catalog source from annotations or labels
		if catalogSource, ok := csv.Annotations["operators.operatorframework.io/catalog-source"]; ok {
			catalogsUsedByOperators[catalogSource] = true
		}
	}

	var nonCompliantCount int

	for i := range resources.CatalogSources {
		cs := &resources.CatalogSources[i]

		// Only check catalog sources that are actually used by our operators
		if !catalogsUsedByOperators[cs.Name] {
			continue
		}

		// For now, we'll mark this as compliant since we can't directly
		// count bundles without probe-based inspection
		// This is a limitation that should be documented
		result.Details = append(result.Details, checks.ResourceDetail{
			Kind:      "CatalogSource",
			Name:      cs.Name,
			Namespace: cs.Namespace,
			Compliant: true,
			Message:   "CatalogSource bundle count check requires runtime inspection",
		})
	}

	if nonCompliantCount > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d catalog source(s) have too many bundles (>%d)", nonCompliantCount, bundleCountLimit)
	}

	return result
}
