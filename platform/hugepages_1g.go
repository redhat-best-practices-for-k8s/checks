package platform

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckHugepages1GiOnly verifies only 1Gi hugepages are used (not 2Mi).
func CheckHugepages1GiOnly(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			for resourceName := range container.Resources.Requests {
				if resourceName == corev1.ResourceName("hugepages-2Mi") {
					count++
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
						Compliant: false,
						Message:   fmt.Sprintf("Container %q requests 2Mi hugepages", container.Name),
					})
				}
			}
			for resourceName := range container.Resources.Limits {
				if resourceName == corev1.ResourceName("hugepages-2Mi") {
					count++
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
						Compliant: false,
						Message:   fmt.Sprintf("Container %q has 2Mi hugepages limit", container.Name),
					})
				}
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) use 2Mi hugepages (only 1Gi allowed)", count)
	}
	return result
}
