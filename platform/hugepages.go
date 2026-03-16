package platform

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckHugepages verifies hugepage configuration on nodes (probe-based).
func CheckHugepages(resources *checks.DiscoveredResources) checks.CheckResult {
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
		if strings.Contains(stdout, "hugepagesz") || strings.Contains(stdout, "hugepages=") {
			sysStdout, _, sysErr := resources.ProbeExecutor.ExecCommand(ctx, probePod,
				"cat /host/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null")
			if sysErr != nil {
				failedNodes = append(failedNodes, nodeName)
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Node", Name: nodeName, Namespace: "",
					Compliant: false,
					Message:   fmt.Sprintf("Failed to execute probe command: %v", sysErr),
				})
				continue
			}
			nrHugepages := strings.TrimSpace(sysStdout)
			if nrHugepages == "0" {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Node", Name: nodeName, Namespace: "",
					Compliant: false,
					Message:   "Hugepages configured in boot params but nr_hugepages is 0",
				})
			}
		}
	}
	if count > 0 || len(failedNodes) > 0 {
		result.ComplianceStatus = "NonCompliant"
		if count > 0 && len(failedNodes) > 0 {
			result.Reason = fmt.Sprintf("%d node(s) have misconfigured hugepages; %d node(s) failed probe execution", count, len(failedNodes))
		} else if count > 0 {
			result.Reason = fmt.Sprintf("%d node(s) have misconfigured hugepages", count)
		} else {
			result.Reason = fmt.Sprintf("%d node(s) failed probe execution", len(failedNodes))
		}
	}
	return result
}
