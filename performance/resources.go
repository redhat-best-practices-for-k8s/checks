package performance

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckExclusiveCPUPool verifies containers requesting whole CPUs have Guaranteed QoS.
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
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			cpuReq := container.Resources.Requests.Cpu()
			cpuLim := container.Resources.Limits.Cpu()

			if cpuReq.IsZero() || cpuReq.MilliValue()%1000 != 0 {
				continue
			}

			if cpuLim.IsZero() || !cpuReq.Equal(*cpuLim) {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q requests %s whole CPUs but limits (%s) do not match", container.Name, cpuReq.String(), cpuLim.String()),
				})
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) have mismatched exclusive CPU pool configuration", count)
	}
	return result
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
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) missing memory limits", count)
	}
	return result
}
