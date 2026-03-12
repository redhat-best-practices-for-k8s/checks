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
}
