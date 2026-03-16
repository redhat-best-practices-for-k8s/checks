package platform

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var grubKernelArgs = []string{
	"hugepagesz",
	"hugepages",
	"isolcpus",
	"rcu_nocbs",
	"rcu_nocb_poll",
	"nohz_full",
	"tuned.non_isolcpus",
}

// CheckBootParams verifies no non-standard kernel boot parameters are set (probe-based).
func CheckBootParams(resources *checks.DiscoveredResources) checks.CheckResult {
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
		stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, probePod, "cat /host/proc/cmdline")
		if err != nil {
			failedNodes = append(failedNodes, nodeName)
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Node", Name: nodeName, Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("Failed to execute probe command: %v", err),
			})
			continue
		}
		for _, arg := range grubKernelArgs {
			if strings.Contains(stdout, arg) {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Node", Name: nodeName, Namespace: "",
					Compliant: false,
					Message:   fmt.Sprintf("Boot parameter %q found in kernel cmdline", arg),
				})
			}
		}
	}
	if count > 0 || len(failedNodes) > 0 {
		result.ComplianceStatus = "NonCompliant"
		if count > 0 && len(failedNodes) > 0 {
			result.Reason = fmt.Sprintf("%d non-standard boot parameter(s) found; %d node(s) failed probe execution", count, len(failedNodes))
		} else if count > 0 {
			result.Reason = fmt.Sprintf("%d non-standard boot parameter(s) found", count)
		} else {
			result.Reason = fmt.Sprintf("%d node(s) failed probe execution", len(failedNodes))
		}
	}
	return result
}
