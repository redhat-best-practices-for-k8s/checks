package accesscontrol

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckSysPtrace verifies pods with shareProcessNamespace have SYS_PTRACE capability.
func CheckSysPtrace(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var sharedCount, count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if pod.Spec.ShareProcessNamespace == nil || !*pod.Spec.ShareProcessNamespace {
			continue
		}
		sharedCount++

		hasPtrace := false
		for j := range pod.Spec.Containers {
			if containerHasCapability(&pod.Spec.Containers[j], "SYS_PTRACE") {
				hasPtrace = true
				break
			}
		}
		if !hasPtrace {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod has shareProcessNamespace=true but no container has SYS_PTRACE capability",
			})
		}
	}
	if sharedCount == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods with shared process namespace found"
		return result
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d pod(s) with shared PID namespace lack SYS_PTRACE capability", count)
	}
	return result
}
