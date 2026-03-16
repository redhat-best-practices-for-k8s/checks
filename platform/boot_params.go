package platform

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

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
	return ExecuteProbeCheck(resources, checkBootParamsNode, "%d non-standard boot parameter(s) found")
}

func checkBootParamsNode(ctx context.Context, nodeName string, probePod *corev1.Pod, executor checks.ProbeExecutor) NodeCheckResult {
	stdout, _, err := executor.ExecCommand(ctx, probePod, "cat /host/proc/cmdline")
	if err != nil {
		return NodeCheckResult{Failed: true, FailureMessage: err.Error()}
	}

	var violations []checks.ResourceDetail
	for _, arg := range grubKernelArgs {
		if strings.Contains(stdout, arg) {
			violations = append(violations, checks.ResourceDetail{
				Kind:      "Node",
				Name:      nodeName,
				Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("Boot parameter %q found in kernel cmdline", arg),
			})
		}
	}

	return NodeCheckResult{Violations: violations}
}
