package platform

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckIsRedHatRelease verifies that containers are based on Red Hat Enterprise Linux.
func CheckIsRedHatRelease(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if resources.ProbeExecutor == nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = "ProbeExecutor not available for probe-based checks"
		return result
	}

	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var failedContainers int

	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			containerName := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)

			// Check /etc/redhat-release file
			command := "cat /etc/redhat-release"
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			stdout, stderr, err := resources.ProbeExecutor.ExecCommand(ctx, pod, command)
			cancel()

			if err != nil || stderr != "" {
				failedContainers++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Failed to read /etc/redhat-release: %v", err),
				})
				continue
			}

			// Check if the output contains "Red Hat"
			if !strings.Contains(stdout, "Red Hat") {
				failedContainers++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container is not based on RHEL (found: %s)", strings.TrimSpace(stdout)),
				})
			} else {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: true,
					Message:   "Container is based on RHEL",
				})
			}
		}
	}

	if failedContainers > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) are not based on RHEL", failedContainers)
	}

	return result
}
