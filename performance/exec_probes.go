package performance

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckLimitedExecProbes verifies cluster-wide exec probe count is below threshold.
// Certsuite limits total exec probes to less than 10.
func CheckLimitedExecProbes(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var totalExecProbes int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			totalExecProbes += countExecProbes(container)
		}
	}
	if totalExecProbes >= 10 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d exec probes found across cluster (max 10 recommended)", totalExecProbes)
		result.Details = append(result.Details, checks.ResourceDetail{
			Kind: "Cluster", Name: "exec-probes",
			Compliant: false,
			Message:   fmt.Sprintf("Total exec probes: %d (threshold: 10)", totalExecProbes),
		})
	} else {
		result.Details = append(result.Details, checks.ResourceDetail{
			Kind: "Cluster", Name: "exec-probes",
			Compliant: true,
			Message:   fmt.Sprintf("Total exec probes: %d (threshold: 10)", totalExecProbes),
		})
	}
	return result
}

// CheckCPUPinningNoExecProbes verifies CPU-pinned pods do not use exec probes.
func CheckCPUPinningNoExecProbes(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if !hasCPUPinning(pod) {
			continue
		}
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			if countExecProbes(container) > 0 {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("CPU-pinned container %q uses exec probes", container.Name),
				})
			} else {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: true,
					Message:   fmt.Sprintf("CPU-pinned container %q does not use exec probes", container.Name),
				})
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d CPU-pinned container(s) use exec probes", count)
	}
	return result
}

func countExecProbes(container *corev1.Container) int {
	count := 0
	if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
		count++
	}
	if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
		count++
	}
	if container.StartupProbe != nil && container.StartupProbe.Exec != nil {
		count++
	}
	return count
}

func hasCPUPinning(pod *corev1.Pod) bool {
	for j := range pod.Spec.Containers {
		container := &pod.Spec.Containers[j]
		cpuReq := container.Resources.Requests.Cpu()
		cpuLim := container.Resources.Limits.Cpu()
		if !cpuReq.IsZero() && cpuReq.MilliValue()%1000 == 0 && cpuReq.Equal(*cpuLim) {
			return true
		}
	}
	return false
}
