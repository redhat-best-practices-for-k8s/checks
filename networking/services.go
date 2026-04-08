package networking

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckDualStackService verifies services support dual-stack.
func CheckDualStackService(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Services) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No services found"
		return result
	}

	var count int
	for i := range resources.Services {
		svc := &resources.Services[i]
		if svc.Spec.ClusterIP == "None" || svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		policy := svc.Spec.IPFamilyPolicy
		if policy == nil || *policy == corev1.IPFamilyPolicySingleStack {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Service", Name: svc.Name, Namespace: svc.Namespace,
				Compliant: false,
				Message:   "Service does not support dual-stack (ipFamilyPolicy is SingleStack or not set)",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d service(s) do not support dual-stack", count)
	}
	return result
}

var reservedPartnerPorts = map[int32]bool{
	22222: true,
	22623: true,
	22624: true,
}

var ocpReservedPorts = map[int32]bool{
	22623: true,
	22624: true,
}

// CheckReservedPartnerPorts verifies containers don't bind to reserved partner ports.
func CheckReservedPartnerPorts(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkPortUsage(resources, reservedPartnerPorts, "reserved partner port")
}

// CheckOCPReservedPorts verifies containers don't use OCP-reserved ports.
func CheckOCPReservedPorts(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkPortUsage(resources, ocpReservedPorts, "OCP reserved port")
}

func checkPortUsage(resources *checks.DiscoveredResources, portSet map[int32]bool, label string) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		for _, port := range container.Ports {
			if portSet[port.ContainerPort] {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q uses %s %d", container.Name, label, port.ContainerPort),
				})
			}
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) use %ss", count, label)
	}
	return result
}
