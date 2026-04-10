package lifecycle

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckStartupProbe verifies containers have a startupProbe defined.
func CheckStartupProbe(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.StartupProbe == nil {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q does not have a startupProbe", container.Name),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true,
				Message:   fmt.Sprintf("Container %q has a startupProbe", container.Name),
			})
		}
	})

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) missing startupProbe", count)
	}
	return result
}

// CheckReadinessProbe verifies containers have a readinessProbe defined.
func CheckReadinessProbe(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.ReadinessProbe == nil {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q does not have a readinessProbe", container.Name),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true,
				Message:   fmt.Sprintf("Container %q has a readinessProbe", container.Name),
			})
		}
	})

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) missing readinessProbe", count)
	}
	return result
}

// CheckLivenessProbe verifies containers have a livenessProbe defined.
func CheckLivenessProbe(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.LivenessProbe == nil {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q does not have a livenessProbe", container.Name),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true,
				Message:   fmt.Sprintf("Container %q has a livenessProbe", container.Name),
			})
		}
	})

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) missing livenessProbe", count)
	}
	return result
}
