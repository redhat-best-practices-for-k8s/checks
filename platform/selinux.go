package platform

import (
	"context"
	"fmt"
	"strings"
	"time"

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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var count int
	var failedNodes []string
	for nodeName, probePod := range resources.ProbePods {
		stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, probePod, "chroot /host getenforce")
		if err != nil {
			failedNodes = append(failedNodes, nodeName)
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Node", Name: nodeName, Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("Failed to execute probe command: %v", err),
			})
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
	if count > 0 || len(failedNodes) > 0 {
		result.ComplianceStatus = "NonCompliant"
		if count > 0 && len(failedNodes) > 0 {
			result.Reason = fmt.Sprintf("%d node(s) do not have SELinux in Enforcing mode; %d node(s) failed probe execution", count, len(failedNodes))
		} else if count > 0 {
			result.Reason = fmt.Sprintf("%d node(s) do not have SELinux in Enforcing mode", count)
		} else {
			result.Reason = fmt.Sprintf("%d node(s) failed probe execution", len(failedNodes))
		}
	}
	return result
}
