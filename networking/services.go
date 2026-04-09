package networking

import (
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckDualStackService verifies services support IPv6 or dual-stack.
// The certsuite logic:
//   - IPFamilyPolicy == nil -> non-compliant (error: no policy configured)
//   - SingleStack with IPv6 ClusterIP -> compliant
//   - SingleStack with IPv4 ClusterIP -> non-compliant
//   - PreferDualStack or RequireDualStack -> compliant (if properly configured)
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

		ipVersion := getServiceIPVersion(svc)
		if ipVersion == ipVersionUndefined || ipVersion == ipVersionIPv4 {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Service", Name: svc.Name, Namespace: svc.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Service only supports IPv4 (ipVersion: %s)", ipVersion),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Service", Name: svc.Name, Namespace: svc.Namespace,
				Compliant: true,
				Message:   fmt.Sprintf("Service supports IPv6 or dual-stack (ipVersion: %s)", ipVersion),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d service(s) do not support IPv6 or dual-stack", count)
	}
	return result
}

type ipVersion string

const (
	ipVersionIPv4      ipVersion = "IPv4"
	ipVersionIPv6      ipVersion = "IPv6"
	ipVersionDualStack ipVersion = "IPv4v6"
	ipVersionUndefined ipVersion = "undefined"
)

// getServiceIPVersion determines the IP version status of a service,
// matching the certsuite's services.GetServiceIPVersion logic.
func getServiceIPVersion(svc *corev1.Service) ipVersion {
	if svc.Spec.IPFamilyPolicy == nil {
		return ipVersionUndefined
	}

	clusterIPVer := parseIPVersion(svc.Spec.ClusterIP)

	switch *svc.Spec.IPFamilyPolicy {
	case corev1.IPFamilyPolicySingleStack:
		if clusterIPVer == ipVersionIPv6 {
			return ipVersionIPv6
		}
		return ipVersionIPv4
	case corev1.IPFamilyPolicyPreferDualStack, corev1.IPFamilyPolicyRequireDualStack:
		if isDualStack(svc.Spec.ClusterIPs) {
			return ipVersionDualStack
		}
		// Dual-stack policy but not enough IPs; the certsuite returns an error in this case.
		return ipVersionUndefined
	}

	return ipVersionUndefined
}

func parseIPVersion(ip string) ipVersion {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ipVersionUndefined
	}
	if parsed.To4() != nil {
		return ipVersionIPv4
	}
	return ipVersionIPv6
}

func isDualStack(ips []string) bool {
	var hasIPv4, hasIPv6 bool
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
	}
	return hasIPv4 && hasIPv6
}

// reservedPartnerPorts are the Istio ports reserved by partner.
// https://istio.io/latest/docs/ops/deployment/requirements/#ports-used-by-istio
var reservedPartnerPorts = map[int32]bool{
	15443: true, // Istio SNI
	15090: true, // Envoy Prometheus telemetry
	15021: true, // Health checks
	15020: true, // Merged Prometheus telemetry from Istio agent, Envoy, and application
	15014: true, // Control plane monitoring
	15008: true, // HBONE mTLS tunnel port
	15006: true, // Envoy inbound
	15001: true, // Envoy outbound
	15000: true, // Envoy admin port (commands/diagnostics)
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
