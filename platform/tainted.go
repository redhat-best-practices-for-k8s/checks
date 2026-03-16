package platform

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckTainted verifies the kernel is not tainted (probe-based).
func CheckTainted(resources *checks.DiscoveredResources) checks.CheckResult {
	return ExecuteProbeCheck(resources, checkTaintedNode, "%d node(s) have tainted kernels")
}

func checkTaintedNode(ctx context.Context, nodeName string, probePod *corev1.Pod, executor checks.ProbeExecutor) NodeCheckResult {
	stdout, _, err := executor.ExecCommand(ctx, probePod, "cat /host/proc/sys/kernel/tainted")
	if err != nil {
		return NodeCheckResult{Failed: true, FailureMessage: err.Error()}
	}

	val := strings.TrimSpace(stdout)
	if val != "0" {
		return NodeCheckResult{
			Violations: []checks.ResourceDetail{{
				Kind:      "Node",
				Name:      nodeName,
				Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("Kernel taint value is %s (expected 0)", val),
			}},
		}
	}

	return NodeCheckResult{}
}
