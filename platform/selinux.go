package platform

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckSELinuxEnforcing verifies all nodes have SELinux in Enforcing mode (probe-based).
func CheckSELinuxEnforcing(resources *checks.DiscoveredResources) checks.CheckResult {
	return ExecuteProbeCheck(resources, checkSELinuxNode, "%d node(s) do not have SELinux in Enforcing mode")
}

func checkSELinuxNode(ctx context.Context, nodeName string, probePod *corev1.Pod, executor checks.ProbeExecutor) NodeCheckResult {
	stdout, _, err := executor.ExecCommand(ctx, probePod, "chroot /host getenforce")
	if err != nil {
		return NodeCheckResult{Failed: true, FailureMessage: err.Error()}
	}

	val := strings.TrimSpace(stdout)
	if val != "Enforcing" {
		return NodeCheckResult{
			Violations: []checks.ResourceDetail{{
				Kind:      "Node",
				Name:      nodeName,
				Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("SELinux mode is %q (expected Enforcing)", val),
			}},
		}
	}

	return NodeCheckResult{}
}
