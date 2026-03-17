package lifecycle

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckPreStop verifies containers have a preStop lifecycle hook.
func CheckPreStop(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.Lifecycle == nil || container.Lifecycle.PreStop == nil {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q does not have a preStop lifecycle hook", container.Name),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d container(s) missing preStop hook", count)
	}
	return result
}

// CheckPostStart verifies containers have a postStart lifecycle hook.
func CheckPostStart(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.Lifecycle == nil || container.Lifecycle.PostStart == nil {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q does not have a postStart lifecycle hook", container.Name),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d container(s) missing postStart hook", count)
	}
	return result
}
