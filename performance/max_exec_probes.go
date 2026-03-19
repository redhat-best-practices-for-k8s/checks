package performance

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

const minExecProbePeriodSeconds = 10

// CheckMaxResourcesExecProbes verifies that exec probes have periodSeconds >= 10
// to reduce resource overhead from frequent process spawning.
func CheckMaxResourcesExecProbes(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "No pods found"
		return result
	}

	var nonCompliant int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			issues := checkExecProbePeriod(container)
			for _, issue := range issues {
				nonCompliant++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q: %s", container.Name, issue),
				})
			}
		}
	}

	if nonCompliant > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d exec probe(s) have periodSeconds < %d", nonCompliant, minExecProbePeriodSeconds)
	}
	return result
}

func checkExecProbePeriod(container *corev1.Container) []string {
	var issues []string

	if container.LivenessProbe != nil && container.LivenessProbe.Exec != nil {
		if container.LivenessProbe.PeriodSeconds < int32(minExecProbePeriodSeconds) {
			issues = append(issues, fmt.Sprintf("livenessProbe exec has periodSeconds=%d (min %d)", container.LivenessProbe.PeriodSeconds, minExecProbePeriodSeconds))
		}
	}
	if container.ReadinessProbe != nil && container.ReadinessProbe.Exec != nil {
		if container.ReadinessProbe.PeriodSeconds < int32(minExecProbePeriodSeconds) {
			issues = append(issues, fmt.Sprintf("readinessProbe exec has periodSeconds=%d (min %d)", container.ReadinessProbe.PeriodSeconds, minExecProbePeriodSeconds))
		}
	}
	if container.StartupProbe != nil && container.StartupProbe.Exec != nil {
		if container.StartupProbe.PeriodSeconds < int32(minExecProbePeriodSeconds) {
			issues = append(issues, fmt.Sprintf("startupProbe exec has periodSeconds=%d (min %d)", container.StartupProbe.PeriodSeconds, minExecProbePeriodSeconds))
		}
	}

	return issues
}
