package performance

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
)

// CheckExclusiveCPUPool verifies that no pod mixes containers from the exclusive
// CPU pool with containers from the shared CPU pool. A container has exclusive
// CPUs when it has integer CPU limits, non-zero memory limits, and all resource
// requests equal their corresponding limits (Guaranteed QoS with whole CPUs).
func CheckExclusiveCPUPool(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		exclusiveCount := 0
		sharedCount := 0

		for j := range pod.Spec.Containers {
			if hasExclusiveCPUs(&pod.Spec.Containers[j]) {
				exclusiveCount++
			} else {
				sharedCount++
			}
		}

		if exclusiveCount > 0 && sharedCount > 0 {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message: fmt.Sprintf("Pod has containers whose CPUs belong to different pools (shared: %d, exclusive: %d)",
					sharedCount, exclusiveCount),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true,
				Message:   "Pod has no containers whose CPUs belong to different pools",
			})
		}
	}

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) mix exclusive and shared CPU pool containers", count)
	}
	return result
}

// hasExclusiveCPUs checks whether a container has exclusive CPUs assigned.
// A container runs in the exclusive CPU pool when it has Guaranteed QoS
// (requests == limits for both CPU and memory) with integer CPU limits.
func hasExclusiveCPUs(container *corev1.Container) bool {
	cpuLim := container.Resources.Limits.Cpu()
	memLim := container.Resources.Limits.Memory()

	if cpuLim.IsZero() || memLim.IsZero() {
		return false
	}

	// CPU limits must be a whole number (not fractional like 500m).
	if cpuLim.MilliValue()%1000 != 0 {
		return false
	}

	// Guaranteed QoS: requests must equal limits for both CPU and memory.
	cpuReq := container.Resources.Requests.Cpu()
	memReq := container.Resources.Requests.Memory()

	return cpuLim.Cmp(*cpuReq) == 0 && memLim.Cmp(*memReq) == 0
}

// CheckRTAppsNoExecProbes verifies RT containers don't use exec probes.
func CheckRTAppsNoExecProbes(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		isRT := pod.Annotations["rt-app"] == "true" || pod.Annotations["realtime"] == "true"
		if !isRT {
			continue
		}

		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			if countExecProbes(container) > 0 {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("RT container %q uses exec probe", container.Name),
				})
			} else {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: true,
					Message:   fmt.Sprintf("RT container %q does not use exec probes", container.Name),
				})
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d RT container(s) use exec probes", count)
	}
	return result
}

// CheckMemoryLimit verifies containers have memory limits set.
func CheckMemoryLimit(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			memLim := container.Resources.Limits.Memory()
			if memLim.IsZero() {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q does not have memory limits set", container.Name),
				})
			} else {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: true,
					Message:   fmt.Sprintf("Container %q has memory limits set (%s)", container.Name, memLim.String()),
				})
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) missing memory limits", count)
	}
	return result
}
