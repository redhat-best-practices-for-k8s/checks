package accesscontrol

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// podCheckFunc is a predicate that checks if a pod violates a host-level security constraint.
type podCheckFunc func(pod *corev1.Pod) bool

// checkPodHostField verifies pods do not enable a specific host-level field.
func checkPodHostField(resources *checks.DiscoveredResources, checkFunc podCheckFunc, fieldName string) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if checkFunc(pod) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false, Message: fmt.Sprintf("%s is set to true", fieldName),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d pod(s) have %s enabled", count, fieldName)
	}
	return result
}

// CheckHostNetwork verifies pods do not use HostNetwork.
func CheckHostNetwork(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkPodHostField(resources, func(pod *corev1.Pod) bool {
		return pod.Spec.HostNetwork
	}, "HostNetwork")
}

// CheckHostPath verifies pods do not use HostPath volumes.
func CheckHostPath(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for _, vol := range pod.Spec.Volumes {
			if vol.HostPath != nil && vol.HostPath.Path != "" {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Volume %q uses HostPath %s", vol.Name, vol.HostPath.Path),
				})
				break // one detail per pod
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d pod(s) use HostPath volumes", count)
	}
	return result
}

// CheckHostIPC verifies pods do not use HostIPC.
func CheckHostIPC(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkPodHostField(resources, func(pod *corev1.Pod) bool {
		return pod.Spec.HostIPC
	}, "HostIPC")
}

// CheckHostPID verifies pods do not use HostPID.
func CheckHostPID(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkPodHostField(resources, func(pod *corev1.Pod) bool {
		return pod.Spec.HostPID
	}, "HostPID")
}

// CheckContainerHostPort verifies containers do not use HostPort.
func CheckContainerHostPort(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		for _, port := range container.Ports {
			if port.HostPort != 0 {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q uses HostPort %d", container.Name, port.HostPort),
				})
			}
		}
	})
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d container(s) use HostPort", count)
	}
	return result
}
