package platform

import (
	"context"
	"fmt"
	"strings"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckSELinuxEnforcing verifies all nodes have SELinux in Enforcing mode (probe-based).
func CheckSELinuxEnforcing(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if resources.ProbeExecutor == nil || len(resources.ProbePods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "Probe pods not available"
		return result
	}

	ctx := context.Background()
	var count int
	for nodeName, probePod := range resources.ProbePods {
		stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, probePod, "chroot /host getenforce")
		if err != nil {
			continue
		}
		val := strings.TrimSpace(stdout)
		if val != "Enforcing" {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Node", Name: nodeName, Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("SELinux mode is %q (expected Enforcing)", val),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d node(s) do not have SELinux in Enforcing mode", count)
	}
	return result
}
