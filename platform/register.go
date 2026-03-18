package platform

import "github.com/redhat-best-practices-for-k8s/checks"

func init() {
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-boot-params", Category: "platform",
		Description: "Verifies no non-standard kernel boot parameters are set",
		Remediation: "Use MachineConfig to manage kernel boot parameters",
		CatalogID:   "platform-alteration-boot-params",
		Fn:          CheckBootParams,
	})
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-hugepages-config", Category: "platform",
		Description: "Verifies hugepage configuration is consistent",
		Remediation: "Configure hugepages via MachineConfig or performance profile",
		CatalogID:   "platform-alteration-hugepages-config",
		Fn:          CheckHugepages,
	})
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-sysctl-config", Category: "platform",
		Description: "Verifies sysctl settings are not modified outside MachineConfig",
		Remediation: "Use MachineConfig to manage sysctl settings",
		CatalogID:   "platform-alteration-sysctl-config",
		Fn:          CheckSysctl,
	})
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-tainted-node-kernel", Category: "platform",
		Description: "Verifies the kernel is not tainted",
		Remediation: "Investigate and resolve kernel taint causes",
		CatalogID:   "platform-alteration-tainted-node-kernel",
		Fn:          CheckTainted,
	})
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-service-mesh-usage", Category: "platform",
		Description: "Verifies pods do not use service mesh (Istio) sidecars",
		Remediation: "Remove Istio sidecar injection if not required",
		CatalogID:   "platform-alteration-service-mesh-usage",
		Fn:          CheckServiceMeshUsage,
	})
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-hugepages-2m-only", Category: "platform",
		Description: "Verifies only 2Mi hugepages are used (not 1Gi)",
		Remediation: "Use 2Mi hugepages instead of 1Gi",
		CatalogID:   "platform-alteration-hugepages-2m-only",
		Fn:          CheckHugepages2MiOnly,
	})
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-ocp-node-count", Category: "platform",
		Description: "Verifies cluster has minimum recommended number of worker nodes",
		Remediation: "Ensure cluster has at least 3 worker nodes",
		CatalogID:   "platform-alteration-ocp-node-count",
		Fn:          CheckNodeCount,
	})
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-hugepages-1g-only", Category: "platform",
		Description: "Verifies only 1Gi hugepages are used (not 2Mi)",
		Remediation: "Use 1Gi hugepages instead of 2Mi",
		CatalogID:   "platform-alteration-hugepages-1g-only",
		Fn:          CheckHugepages1GiOnly,
	})
	checks.Register(checks.CheckInfo{
		Name: "platform-alteration-is-selinux-enforcing", Category: "platform",
		Description: "Verifies all nodes have SELinux in Enforcing mode",
		Remediation: "Set SELinux to Enforcing mode on all nodes",
		CatalogID:   "platform-alteration-is-selinux-enforcing",
		Fn:          CheckSELinuxEnforcing,
	})
	checks.Register(checks.CheckInfo{
		Name:        "platform-alteration-ocp-lifecycle",
		Category:    "platform",
		Description: "Verifies OpenShift version is not end-of-life",
		Remediation: "Upgrade to a supported OpenShift version",
		CatalogID:   "ocp-lifecycle",
		Fn:          CheckOCPLifecycle,
	})
	checks.Register(checks.CheckInfo{
		Name:        "platform-alteration-ocp-node-os-lifecycle",
		Category:    "platform",
		Description: "Verifies node operating systems are compatible with OCP version",
		Remediation: "Ensure control plane nodes run RHCOS and all nodes are compatible",
		CatalogID:   "ocp-node-os-lifecycle",
		Fn:          CheckOCPNodeOSLifecycle,
	})
	checks.Register(checks.CheckInfo{
		Name:        "platform-alteration-cluster-operator-health",
		Category:    "platform",
		Description: "Verifies all cluster operators are in Available state",
		Remediation: "Investigate and fix cluster operators that are not Available",
		CatalogID:   "cluster-operator-health",
		Fn:          CheckClusterOperatorHealth,
	})
	checks.Register(checks.CheckInfo{
		Name:        "platform-alteration-isredhat-release",
		Category:    "platform",
		Description: "Verifies containers are based on Red Hat Enterprise Linux",
		Remediation: "Use RHEL-based container images",
		CatalogID:   "isredhat-release",
		Fn:          CheckIsRedHatRelease,
	})
	checks.Register(checks.CheckInfo{
		Name:        "platform-alteration-hyperthread-enable",
		Category:    "platform",
		Description: "Verifies bare metal nodes have hyperthreading enabled",
		Remediation: "Enable hyperthreading in BIOS settings",
		CatalogID:   "hyperthread-enable",
		Fn:          CheckHyperthreadEnable,
	})
	checks.Register(checks.CheckInfo{
		Name:        "platform-alteration-base-image",
		Category:    "platform",
		Description: "Verifies containers have not modified their base image by installing packages",
		Remediation: "Build packages into the container image rather than installing at runtime",
		CatalogID:   "base-image",
		Fn:          CheckUnalteredBaseImage,
	})
}
