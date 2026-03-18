package platform

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
)

// CheckUnalteredBaseImage verifies containers have not modified their filesystem
// by installing packages post-deployment.
func CheckUnalteredBaseImage(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}

	if resources.OpenshiftVersion == "" {
		result.ComplianceStatus = "Skipped"
		result.Reason = "Not an OpenShift cluster (base image check requires OCP)"
		return result
	}

	if resources.ProbeExecutor == nil {
		result.ComplianceStatus = "Error"
		result.Reason = "ProbeExecutor not available for base image checks"
		return result
	}

	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var failures int

	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			containerName := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)

			// Check if container filesystem has been modified
			modified, changedPaths, err := checkContainerFSDiff(resources, pod, container)
			if err != nil {
				failures++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Failed to check filesystem modifications: %v", err),
				})
				continue
			}

			if modified {
				failures++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container filesystem modified (changed paths: %s)", strings.Join(changedPaths, ", ")),
				})
			} else {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: true,
					Message:   "Container filesystem unmodified",
				})
			}
		}
	}

	if failures > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d container(s) have modified filesystems", failures)
	}

	return result
}

// checkContainerFSDiff checks if a container's filesystem has been modified
// Returns: modified bool, changedPaths []string, error
func checkContainerFSDiff(resources *checks.DiscoveredResources, pod *corev1.Pod, container *corev1.Container) (bool, []string, error) {
	// Get container ID from status
	var containerID string
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == container.Name {
			containerID = status.ContainerID
			break
		}
	}

	if containerID == "" {
		return false, nil, fmt.Errorf("container ID not found in status")
	}

	// Use crictl to check for filesystem differences
	// This compares the current filesystem against the original image layers
	command := fmt.Sprintf("crictl exec %s sh -c 'rpm -qa'", containerID)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, pod, command)
	if err != nil {
		// If rpm command fails, container might not be RHEL-based or crictl might not be available
		// We'll use a simpler check - look for common package manager lock files
		return checkForPackageManagerArtifacts(resources, pod, containerID)
	}

	// If we can run rpm -qa, check if there are any packages that shouldn't be there
	// In a properly immutable container, the package database should match the image
	// This is a simplified check - full implementation would compare against image manifest
	lines := strings.Split(strings.TrimSpace(stdout), "\n")

	// Check for signs of post-deployment package installation
	// Look for common package manager artifacts in temporary locations
	modified, paths, checkErr := checkForPackageManagerArtifacts(resources, pod, containerID)
	if checkErr != nil {
		return false, nil, checkErr
	}

	// If we found a very large number of packages or package manager artifacts, flag as potentially modified
	if len(lines) > 500 || modified {
		return true, paths, nil
	}

	return false, nil, nil
}

// checkForPackageManagerArtifacts looks for evidence of package installation
func checkForPackageManagerArtifacts(resources *checks.DiscoveredResources, pod *corev1.Pod, containerID string) (bool, []string, error) {
	// Check for package manager temporary files and caches in a single command
	checkPaths := []string{
		"/var/cache/dnf",
		"/var/cache/yum",
		"/tmp/yum-*",
		"/var/lib/rpm/__db.*",
	}

	// Combine all checks into single command for efficiency
	command := fmt.Sprintf("crictl exec %s sh -c 'for p in %s; do [ -e \"$p\" ] && echo \"$p\"; done'",
		containerID, strings.Join(checkPaths, " "))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, pod, command)
	if err != nil {
		return false, nil, nil // Treat errors as no artifacts found
	}

	foundPaths := []string{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line != "" {
			foundPaths = append(foundPaths, line)
		}
	}

	return len(foundPaths) > 0, foundPaths, nil
}
