package accesscontrol

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckNonRootUser verifies containers run as non-root.
// A container is compliant if RunAsNonRoot=true OR RunAsUser is set to a non-zero value.
func CheckNonRootUser(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachPodContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if !isContainerRunAsNonRoot(pod, container) && !isContainerRunAsNonRootUserID(pod, container) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q does not have runAsNonRoot=true or runAsUser!=0", container.Name),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) may run as root", count)
	}
	return result
}

func isContainerRunAsNonRoot(pod *corev1.Pod, container *corev1.Container) bool {
	if container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil {
		return *container.SecurityContext.RunAsNonRoot
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
		return *pod.Spec.SecurityContext.RunAsNonRoot
	}
	return false
}

func isContainerRunAsNonRootUserID(pod *corev1.Pod, container *corev1.Container) bool {
	if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil {
		return *container.SecurityContext.RunAsUser != 0
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil {
		return *pod.Spec.SecurityContext.RunAsUser != 0
	}
	return false
}

// CheckPrivilegeEscalation verifies containers do not allow privilege escalation.
func CheckPrivilegeEscalation(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachPodContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.SecurityContext != nil &&
			container.SecurityContext.AllowPrivilegeEscalation != nil &&
			*container.SecurityContext.AllowPrivilegeEscalation {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q has allowPrivilegeEscalation set to true", container.Name),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) allow privilege escalation", count)
	}
	return result
}

// CheckReadOnlyFilesystem verifies containers set readOnlyRootFilesystem to true.
func CheckReadOnlyFilesystem(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachPodContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.SecurityContext == nil ||
			container.SecurityContext.ReadOnlyRootFilesystem == nil ||
			!*container.SecurityContext.ReadOnlyRootFilesystem {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q does not set readOnlyRootFilesystem to true", container.Name),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) do not set readOnlyRootFilesystem", count)
	}
	return result
}

// Check1337UID verifies pods do not run as UID 1337 (Istio conflict).
func Check1337UID(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if pod.Spec.SecurityContext != nil &&
			pod.Spec.SecurityContext.RunAsUser != nil &&
			*pod.Spec.SecurityContext.RunAsUser == 1337 {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod SecurityContext RunAsUser is set to 1337 (reserved by Istio)",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) use UID 1337", count)
	}
	return result
}

// CheckSecurityContext categorizes container security contexts (SCC check).
func CheckSecurityContext(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
		for j := range allContainers {
			container := &allContainers[j]
			category := categorizeSCC(pod, container)
			if category > categoryID1NoUID0 {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q requires elevated SCC (category %d)", container.Name, category),
				})
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) require elevated SCC", count)
	}
	return result
}

// SCC category constants matching certsuite securitycontextcontainer categories.
const (
	categoryID1       = 0 // Most restrictive
	categoryID1NoUID0 = 1 // Restrictive but no UID 0 requirement
	categoryID2       = 2 // Needs some elevated privs
	categoryID3       = 3 // Needs significant elevated privs
	categoryID4       = 4 // Privileged
)

func categorizeSCC(pod *corev1.Pod, container *corev1.Container) int {
	if container.SecurityContext == nil {
		return categoryID1NoUID0
	}
	sc := container.SecurityContext

	if sc.Privileged != nil && *sc.Privileged {
		return categoryID4
	}

	for _, port := range container.Ports {
		if port.HostPort != 0 {
			return categoryID3
		}
	}

	if sc.Capabilities != nil {
		for _, cap := range sc.Capabilities.Add {
			switch string(cap) {
			case "ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "BPF":
				return categoryID3
			}
		}
	}

	if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
		return categoryID2
	}

	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		podNonRoot := pod.Spec.SecurityContext != nil &&
			pod.Spec.SecurityContext.RunAsNonRoot != nil &&
			*pod.Spec.SecurityContext.RunAsNonRoot
		if !podNonRoot {
			return categoryID1NoUID0
		}
	}

	return categoryID1
}
