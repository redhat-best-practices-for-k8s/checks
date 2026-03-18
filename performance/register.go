package performance

import "github.com/redhat-best-practices-for-k8s/checks"

func init() {
	checks.Register(checks.CheckInfo{
		Name: "performance-exclusive-cpu-pool", Category: "performance",
		Description: "Verifies containers requesting whole CPUs use exclusive CPU pool (Guaranteed QoS)",
		Remediation: "Set CPU requests equal to limits with whole-number values for exclusive CPU allocation",
		CatalogID:   "performance-exclusive-cpu-pool",
		Fn:          CheckExclusiveCPUPool,
	})
	checks.Register(checks.CheckInfo{
		Name: "performance-rt-apps-no-exec-probes", Category: "performance",
		Description: "Verifies real-time containers do not use exec probes",
		Remediation: "Use httpGet or tcpSocket probes instead of exec for RT workloads",
		CatalogID:   "performance-rt-apps-no-exec-probes",
		Fn:          CheckRTAppsNoExecProbes,
	})
	checks.Register(checks.CheckInfo{
		Name: "performance-limit-memory-allocation", Category: "performance",
		Description: "Verifies containers have memory limits set",
		Remediation: "Set resources.limits.memory on all containers",
		CatalogID:   "performance-limit-memory-allocation",
		Fn:          CheckMemoryLimit,
	})
	checks.Register(checks.CheckInfo{
		Name: "performance-limited-use-of-exec-probes", Category: "performance",
		Description: "Verifies cluster-wide exec probe count is below threshold (10)",
		Remediation: "Reduce the number of exec probes or use httpGet/tcpSocket probes",
		CatalogID:   "performance-limited-use-of-exec-probes",
		Fn:          CheckLimitedExecProbes,
	})
	checks.Register(checks.CheckInfo{
		Name: "performance-cpu-pinning-no-exec-probes", Category: "performance",
		Description: "Verifies CPU-pinned pods do not use exec probes",
		Remediation: "Use httpGet or tcpSocket probes for CPU-pinned workloads",
		CatalogID:   "performance-cpu-pinning-no-exec-probes",
		Fn:          CheckCPUPinningNoExecProbes,
	})
	checks.Register(checks.CheckInfo{
		Name: "performance-max-resources-exec-probes", Category: "performance",
		Description: "Verifies exec probes have periodSeconds >= 10",
		Remediation: "Set periodSeconds to at least 10 on exec probes to reduce resource overhead",
		CatalogID:   "performance-max-resources-exec-probes",
		Fn:          CheckMaxResourcesExecProbes,
	})
	checks.Register(checks.CheckInfo{
		Name:        "performance-shared-cpu-pool-non-rt-scheduling-policy",
		Category:    "performance",
		Description: "Verifies shared CPU pool containers use non-RT scheduling (SCHED_OTHER)",
		Remediation: "Use SCHED_OTHER scheduling policy for non-guaranteed pods",
		CatalogID:   "shared-cpu-pool-non-rt-scheduling-policy",
		Fn:          CheckSharedCPUPoolSchedulingPolicy,
	})
	checks.Register(checks.CheckInfo{
		Name:        "performance-exclusive-cpu-pool-rt-scheduling-policy",
		Category:    "performance",
		Description: "Verifies exclusive CPU pool containers use RT scheduling (SCHED_FIFO/RR)",
		Remediation: "Configure RT scheduling policy for guaranteed pods with exclusive CPUs",
		CatalogID:   "exclusive-cpu-pool-rt-scheduling-policy",
		Fn:          CheckExclusiveCPUPoolSchedulingPolicy,
	})
	checks.Register(checks.CheckInfo{
		Name:        "performance-isolated-cpu-pool-rt-scheduling-policy",
		Category:    "performance",
		Description: "Verifies isolated CPU pool containers use RT scheduling (SCHED_FIFO/RR)",
		Remediation: "Configure RT scheduling policy for pods with isolated CPUs",
		CatalogID:   "isolated-cpu-pool-rt-scheduling-policy",
		Fn:          CheckIsolatedCPUPoolSchedulingPolicy,
	})
}
