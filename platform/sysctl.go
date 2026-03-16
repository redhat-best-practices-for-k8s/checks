package platform

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var mcSysctls = []string{
	"net.ipv4.conf.all.accept_redirects",
	"net.ipv6.conf.all.accept_redirects",
	"net.ipv4.conf.all.secure_redirects",
	"kernel.core_pattern",
}

// CheckSysctl verifies sysctl settings are not modified outside of MachineConfig (probe-based).
func CheckSysctl(resources *checks.DiscoveredResources) checks.CheckResult {
	return ExecuteProbeCheck(resources, checkSysctlNode, "%d non-default sysctl setting(s) found")
}

func checkSysctlNode(ctx context.Context, nodeName string, probePod *corev1.Pod, executor checks.ProbeExecutor) NodeCheckResult {
	var violations []checks.ResourceDetail

	for _, sysctl := range mcSysctls {
		cmd := fmt.Sprintf("chroot /host sysctl -n %s 2>/dev/null", sysctl)
		stdout, _, err := executor.ExecCommand(ctx, probePod, cmd)
		if err != nil {
			// Fail fast on first error for this node
			return NodeCheckResult{Failed: true, FailureMessage: err.Error()}
		}

		val := strings.TrimSpace(stdout)
		if isNonDefaultSysctl(sysctl, val) {
			violations = append(violations, checks.ResourceDetail{
				Kind:      "Node",
				Name:      nodeName,
				Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("Sysctl %s has non-default value %q", sysctl, val),
			})
		}
	}

	return NodeCheckResult{Violations: violations}
}

func isNonDefaultSysctl(name, value string) bool {
	defaults := map[string]string{
		"net.ipv4.conf.all.accept_redirects": "0",
		"net.ipv6.conf.all.accept_redirects": "0",
		"net.ipv4.conf.all.secure_redirects": "1",
		"kernel.core_pattern":                "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h",
	}
	if expected, ok := defaults[name]; ok {
		return value != expected
	}
	return false
}
