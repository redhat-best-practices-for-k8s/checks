package networking

import "github.com/redhat-best-practices-for-k8s/checks"

func init() {
	checks.Register(checks.CheckInfo{
		Name: "networking-dual-stack-service", Category: "networking",
		Description: "Verifies services support dual-stack (both IPv4 and IPv6)",
		Remediation: "Set spec.ipFamilyPolicy to PreferDualStack or RequireDualStack",
		CatalogID:   "networking-dual-stack-service",
		Fn:          CheckDualStackService,
	})
	checks.Register(checks.CheckInfo{
		Name: "networking-network-policy-deny-all", Category: "networking",
		Description: "Verifies a default-deny NetworkPolicy exists in the namespace",
		Remediation: "Create a NetworkPolicy that denies all ingress and egress by default",
		CatalogID:   "networking-network-policy-deny-all",
		Fn:          CheckNetworkPolicyDenyAll,
	})
	checks.Register(checks.CheckInfo{
		Name: "networking-reserved-partner-ports", Category: "networking",
		Description: "Verifies containers do not bind to reserved partner ports (22222, 22623, 22624)",
		Remediation: "Use non-reserved ports for container services",
		CatalogID:   "networking-reserved-partner-ports",
		Fn:          CheckReservedPartnerPorts,
	})
	checks.Register(checks.CheckInfo{
		Name: "networking-ocp-reserved-ports-usage", Category: "networking",
		Description: "Verifies containers do not use OpenShift reserved ports (22623, 22624)",
		Remediation: "Avoid using OpenShift reserved ports",
		CatalogID:   "networking-ocp-reserved-ports-usage",
		Fn:          CheckOCPReservedPorts,
	})
	checks.Register(checks.CheckInfo{
		Name: "networking-restart-on-reboot-sriov-pod", Category: "networking",
		Description: "Verifies SR-IOV pods have restart-on-reboot=true label",
		Remediation: "Add label restart-on-reboot=true to SR-IOV pods",
		CatalogID:   "networking-restart-on-reboot-sriov-pod",
		Fn:          CheckSRIOVRestartLabel,
	})
	checks.Register(checks.CheckInfo{
		Name:        "networking-undeclared-container-ports-usage",
		Category:    "networking",
		Description: "Verifies all listening ports are declared in container specs",
		Remediation: "Declare all listening ports in container port specifications",
		CatalogID:   "networking-undeclared-container-ports-usage",
		Fn:          CheckUndeclaredContainerPorts,
	})
	checks.Register(checks.CheckInfo{
		Name:        "networking-network-attachment-definition-sriov-mtu",
		Category:    "networking",
		Description: "Verifies SR-IOV network attachment definitions have MTU configured",
		Remediation: "Set MTU explicitly in NetworkAttachmentDefinition or SriovNetwork specs",
		CatalogID:   "network-attachment-definition-sriov-mtu",
		Fn:          CheckSRIOVNetworkAttachmentDefinitionMTU,
	})
	checks.Register(checks.CheckInfo{
		Name:        "networking-icmpv4-connectivity",
		Category:    "networking",
		Description: "Verifies IPv4 ICMP connectivity between pods",
		Remediation: "Ensure network policies and firewall rules allow ICMP traffic",
		CatalogID:   "icmpv4-connectivity",
		Fn:          CheckICMPv4Connectivity,
	})
	checks.Register(checks.CheckInfo{
		Name:        "networking-icmpv6-connectivity",
		Category:    "networking",
		Description: "Verifies IPv6 ICMP connectivity between pods",
		Remediation: "Ensure network policies and firewall rules allow ICMPv6 traffic",
		CatalogID:   "icmpv6-connectivity",
		Fn:          CheckICMPv6Connectivity,
	})
	checks.Register(checks.CheckInfo{
		Name:        "networking-icmpv4-connectivity-multus",
		Category:    "networking",
		Description: "Verifies IPv4 ICMP connectivity between pods on Multus networks",
		Remediation: "Check Multus network configuration and ICMP policies",
		CatalogID:   "icmpv4-connectivity-multus",
		Fn:          CheckICMPv4ConnectivityMultus,
	})
	checks.Register(checks.CheckInfo{
		Name:        "networking-icmpv6-connectivity-multus",
		Category:    "networking",
		Description: "Verifies IPv6 ICMP connectivity between pods on Multus networks",
		Remediation: "Check Multus network configuration and ICMPv6 policies",
		CatalogID:   "icmpv6-connectivity-multus",
		Fn:          CheckICMPv6ConnectivityMultus,
	})
}
