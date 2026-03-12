package accesscontrol

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckPodRequests verifies all containers have CPU and memory resource requests set.
func CheckPodRequests(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
		for j := range allContainers {
			container := &allContainers[j]
			cpuReq := container.Resources.Requests.Cpu()
			memReq := container.Resources.Requests.Memory()
			if cpuReq.IsZero() || memReq.IsZero() {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q missing resource requests (cpu: %s, memory: %s)", container.Name, cpuReq.String(), memReq.String()),
				})
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d container(s) missing CPU or memory requests", count)
	}
	return result
}
