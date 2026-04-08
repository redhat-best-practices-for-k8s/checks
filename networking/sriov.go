package networking

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckSRIOVRestartLabel verifies pods using SR-IOV have the restart-on-reboot label.
func CheckSRIOVRestartLabel(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var sriovCount, count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if !isPodUsingSRIOV(pod) {
			continue
		}
		sriovCount++

		val, ok := pod.Labels["restart-on-reboot"]
		if !ok || val != "true" {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "SR-IOV pod missing restart-on-reboot=true label",
			})
		}
	}
	if sriovCount == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No SR-IOV pods found"
		return result
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d SR-IOV pod(s) missing restart-on-reboot label", count)
	}
	return result
}

func isPodUsingSRIOV(pod *corev1.Pod) bool {
	_, hasNetworks := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
	if !hasNetworks {
		return false
	}
	return hasSRIOVResource(pod)
}

func hasSRIOVResource(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		for resourceName := range container.Resources.Requests {
			if strings.HasPrefix(string(resourceName), "openshift.io/") {
				return true
			}
		}
		for resourceName := range container.Resources.Limits {
			if strings.HasPrefix(string(resourceName), "openshift.io/") {
				return true
			}
		}
	}
	return false
}
