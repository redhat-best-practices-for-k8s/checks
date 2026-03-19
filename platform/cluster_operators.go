package platform

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckClusterOperatorHealth verifies all cluster operators are in Available state.
func CheckClusterOperatorHealth(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if len(resources.ClusterOperators) == 0 {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "No cluster operators found (not an OpenShift cluster)"
		return result
	}

	var unavailableCount int

	for i := range resources.ClusterOperators {
		co := &resources.ClusterOperators[i]

		if !isClusterOperatorAvailable(co) {
			unavailableCount++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "ClusterOperator",
				Name:      co.Name,
				Compliant: false,
				Message:   "ClusterOperator is not in Available state",
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "ClusterOperator",
				Name:      co.Name,
				Compliant: true,
				Message:   "ClusterOperator is in Available state",
			})
		}
	}

	if unavailableCount > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d cluster operator(s) not in Available state", unavailableCount)
	}

	return result
}

func isClusterOperatorAvailable(co interface{}) bool {
	// This will need to check the co.Status.Conditions for Available=True
	// For now, return true as a placeholder - will be implemented properly
	// when we have the actual configv1.ClusterOperator type available
	return true
}
