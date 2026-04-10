package lifecycle

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckTopologySpreadConstraints verifies Deployments have proper TopologySpreadConstraints.
// If defined, constraints must include both hostname and zone topology keys.
func CheckTopologySpreadConstraints(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Deployments) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No deployments found"
		return result
	}

	var count int
	for i := range resources.Deployments {
		deploy := &resources.Deployments[i]
		constraints := deploy.Spec.Template.Spec.TopologySpreadConstraints
		if len(constraints) == 0 {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Deployment", Name: deploy.Name, Namespace: deploy.Namespace,
				Compliant: true,
				Message:   "No TopologySpreadConstraints defined (compliant by default)",
			})
			continue
		}

		hasHostname := false
		hasZone := false
		for _, c := range constraints {
			switch c.TopologyKey {
			case "kubernetes.io/hostname":
				hasHostname = true
			case "topology.kubernetes.io/zone":
				hasZone = true
			}
		}
		if !hasHostname || !hasZone {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Deployment", Name: deploy.Name, Namespace: deploy.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("TopologySpreadConstraints defined but missing required keys (hostname=%t, zone=%t)", hasHostname, hasZone),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Deployment", Name: deploy.Name, Namespace: deploy.Namespace,
				Compliant: true,
				Message:   "TopologySpreadConstraints include both hostname and zone keys",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d deployment(s) have incomplete TopologySpreadConstraints", count)
	}
	return result
}
