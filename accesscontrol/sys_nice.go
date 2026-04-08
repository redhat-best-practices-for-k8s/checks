package accesscontrol

import (
	"fmt"
	"strings"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckSysNiceRealtime verifies that containers running on nodes with a realtime
// kernel have the SYS_NICE capability, which is required for DPDK applications
// to switch to SCHED_FIFO scheduling.
func CheckSysNiceRealtime(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	// Build a map of node names to RT kernel status
	rtNodes := make(map[string]bool)
	for i := range resources.Nodes {
		node := &resources.Nodes[i]
		kernelVersion := node.Status.NodeInfo.KernelVersion
		if strings.Contains(kernelVersion, "rt") {
			rtNodes[node.Name] = true
		}
	}

	if len(rtNodes) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No nodes with realtime kernel found"
		return result
	}

	var nonCompliant int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if pod.Spec.NodeName == "" || !rtNodes[pod.Spec.NodeName] {
			continue
		}

		allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
		for j := range allContainers {
			container := &allContainers[j]
			if !containerHasCapability(container, "SYS_NICE") {
				nonCompliant++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q on RT node %q lacks SYS_NICE capability", container.Name, pod.Spec.NodeName),
				})
			}
		}
	}

	if nonCompliant > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) on RT nodes lack SYS_NICE capability", nonCompliant)
	}
	return result
}
