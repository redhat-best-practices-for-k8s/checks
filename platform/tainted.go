package platform

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckTainted verifies the kernel is not tainted (probe-based).
func CheckTainted(resources *checks.DiscoveredResources) checks.CheckResult {
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
		stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, probePod, "cat /host/proc/sys/kernel/tainted")
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
		if val != "0" {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Node", Name: nodeName, Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("Kernel taint value is %s (expected 0)", val),
			})
		}
	}
	if count > 0 || len(failedNodes) > 0 {
		result.ComplianceStatus = "NonCompliant"
		if count > 0 && len(failedNodes) > 0 {
			result.Reason = fmt.Sprintf("%d node(s) have tainted kernels; %d node(s) failed probe execution", count, len(failedNodes))
		} else if count > 0 {
			result.Reason = fmt.Sprintf("%d node(s) have tainted kernels", count)
		} else {
			result.Reason = fmt.Sprintf("%d node(s) failed probe execution", len(failedNodes))
		}
	}
	return result
}
