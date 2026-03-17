package observability

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckTerminationPolicy verifies containers set terminationMessagePolicy to FallbackToLogsOnError.
func CheckTerminationPolicy(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachPodContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.TerminationMessagePolicy != corev1.TerminationMessageFallbackToLogsOnError {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message: fmt.Sprintf("Container %q terminationMessagePolicy is %q, expected FallbackToLogsOnError",
					container.Name, container.TerminationMessagePolicy),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d container(s) do not use FallbackToLogsOnError termination policy", count)
	}
	return result
}
