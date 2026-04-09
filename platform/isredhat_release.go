package platform

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
)

const (
	// redhatReleaseCommand safely checks for /etc/redhat-release existence before reading it.
	// This matches the certsuite's isredhat package behavior.
	redhatReleaseCommand = `if [ -e /etc/redhat-release ]; then cat /etc/redhat-release; else echo "Unknown Base Image"; fi`

	// notRedHatBasedRegex matches the output for a container not based on Red Hat technologies.
	notRedHatBasedRegex = `(?m)Unknown Base Image`

	// rhelVersionRegex matches the expected output for a RHEL-based container.
	rhelVersionRegex = `(?m)Red Hat Enterprise Linux( Server)? release (\d+\.\d+)`
)

var (
	notRedHatRegex     = regexp.MustCompile(notRedHatBasedRegex)
	redHatVersionRegex = regexp.MustCompile(rhelVersionRegex)
)

// isRHEL checks if the output from /etc/redhat-release indicates a RHEL-based image.
// This matches the certsuite's isredhat.IsRHEL function.
func isRHEL(output string) bool {
	// If the 'Unknown Base Image' string appears, return false.
	if notRedHatRegex.MatchString(output) {
		return false
	}
	// Check if it matches the regex for an official RHEL build.
	return redHatVersionRegex.MatchString(output)
}

// CheckIsRedHatRelease verifies that containers are based on Red Hat Enterprise Linux.
// Uses the safer command with file existence check and proper RHEL regex matching,
// matching the certsuite's isredhat package behavior.
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

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			stdout, stderr, err := resources.ProbeExecutor.ExecCommandInContainer(ctx, pod, container.Name, redhatReleaseCommand)
			cancel()

			_ = stderr // stderr may contain harmless warnings (e.g., locale)
			if err != nil {
				failedContainers++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Failed to check /etc/redhat-release: %v", err),
				})
				continue
			}

			if !isRHEL(stdout) {
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
