package platform

import (
	"context"
	"fmt"
	"strings"
	"time"

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
		nodeHasError := false
		for _, sysctl := range mcSysctls {
			cmd := fmt.Sprintf("chroot /host sysctl -n %s 2>/dev/null", sysctl)
			stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, probePod, cmd)
			if err != nil {
				if !nodeHasError {
					failedNodes = append(failedNodes, nodeName)
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind: "Node", Name: nodeName, Namespace: "",
						Compliant: false,
						Message:   fmt.Sprintf("Failed to execute probe command: %v", err),
					})
					nodeHasError = true
				}
				continue
			}
			val := strings.TrimSpace(stdout)
			if isNonDefaultSysctl(sysctl, val) {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Node", Name: nodeName, Namespace: "",
					Compliant: false,
					Message:   fmt.Sprintf("Sysctl %s has non-default value %q", sysctl, val),
				})
			}
		}
	}
	if count > 0 || len(failedNodes) > 0 {
		result.ComplianceStatus = "NonCompliant"
		if count > 0 && len(failedNodes) > 0 {
			result.Reason = fmt.Sprintf("%d non-default sysctl setting(s) found; %d node(s) failed probe execution", count, len(failedNodes))
		} else if count > 0 {
			result.Reason = fmt.Sprintf("%d non-default sysctl setting(s) found", count)
		} else {
			result.Reason = fmt.Sprintf("%d node(s) failed probe execution", len(failedNodes))
		}
	}
	return result
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
