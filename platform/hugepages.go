package platform

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckHugepages verifies hugepage configuration on nodes (probe-based).
func CheckHugepages(resources *checks.DiscoveredResources) checks.CheckResult {
	return ExecuteProbeCheck(resources, checkHugepagesNode, "%d node(s) have misconfigured hugepages")
}

func checkHugepagesNode(ctx context.Context, nodeName string, probePod *corev1.Pod, executor checks.ProbeExecutor) NodeCheckResult {
	stdout, _, err := executor.ExecCommand(ctx, probePod, "cat /host/proc/cmdline")
	if err != nil {
		return NodeCheckResult{Failed: true, FailureMessage: err.Error()}
	}

	// Only check hugepages if configured in boot params
	if !strings.Contains(stdout, "hugepagesz") && !strings.Contains(stdout, "hugepages=") {
		return NodeCheckResult{}
	}

	// Check if hugepages are actually allocated
	sysStdout, _, sysErr := executor.ExecCommand(ctx, probePod,
		"cat /host/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null")
	if sysErr != nil {
		return NodeCheckResult{Failed: true, FailureMessage: sysErr.Error()}
	}

	nrHugepages := strings.TrimSpace(sysStdout)
	if nrHugepages == "0" {
		return NodeCheckResult{
			Violations: []checks.ResourceDetail{{
				Kind:      "Node",
				Name:      nodeName,
				Namespace: "",
				Compliant: false,
				Message:   "Hugepages configured in boot params but nr_hugepages is 0",
			}},
		}
	}

	return NodeCheckResult{}
}
