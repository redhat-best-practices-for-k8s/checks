package performance

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "performance-cpu-pinning-no-exec-probes",
			Category: "performance",
			CatalogID: "performance-cpu-pinning-no-exec-probes",
			Fn:       CheckCPUPinningNoExecProbes,
			Description: PerformanceCpuPinningNoExecProbesDescription,
			Remediation: PerformanceCpuPinningNoExecProbesRemediation,
			BestPracticeReference: PerformanceCpuPinningNoExecProbesBestPracticeRef,
			ExceptionProcess: PerformanceCpuPinningNoExecProbesExceptionProcess,
			ImpactStatement: PerformanceCpuPinningNoExecProbesImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "performance-exclusive-cpu-pool",
			Category: "performance",
			CatalogID: "performance-exclusive-cpu-pool",
			Fn:       CheckExclusiveCPUPool,
			Description: PerformanceExclusiveCpuPoolDescription,
			Remediation: PerformanceExclusiveCpuPoolRemediation,
			BestPracticeReference: PerformanceExclusiveCpuPoolBestPracticeRef,
			ExceptionProcess: PerformanceExclusiveCpuPoolExceptionProcess,
			ImpactStatement: PerformanceExclusiveCpuPoolImpactStatement,
			Qe: true,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "performance-exclusive-cpu-pool-rt-scheduling-policy",
			Category: "performance",
			CatalogID: "exclusive-cpu-pool-rt-scheduling-policy",
			Fn:       CheckExclusiveCPUPoolSchedulingPolicy,
			Description: PerformanceExclusiveCpuPoolRtSchedulingPolicyDescription,
			Remediation: PerformanceExclusiveCpuPoolRtSchedulingPolicyRemediation,
			BestPracticeReference: PerformanceExclusiveCpuPoolRtSchedulingPolicyBestPracticeRef,
			ExceptionProcess: PerformanceExclusiveCpuPoolRtSchedulingPolicyExceptionProcess,
			ImpactStatement: PerformanceExclusiveCpuPoolRtSchedulingPolicyImpactStatement,
			Qe: true,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "performance-isolated-cpu-pool-rt-scheduling-policy",
			Category: "performance",
			CatalogID: "isolated-cpu-pool-rt-scheduling-policy",
			Fn:       CheckIsolatedCPUPoolSchedulingPolicy,
			Description: PerformanceIsolatedCpuPoolRtSchedulingPolicyDescription,
			Remediation: PerformanceIsolatedCpuPoolRtSchedulingPolicyRemediation,
			BestPracticeReference: PerformanceIsolatedCpuPoolRtSchedulingPolicyBestPracticeRef,
			ExceptionProcess: PerformanceIsolatedCpuPoolRtSchedulingPolicyExceptionProcess,
			ImpactStatement: PerformanceIsolatedCpuPoolRtSchedulingPolicyImpactStatement,
			Qe: true,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "performance-limit-memory-allocation",
			Category: "performance",
			CatalogID: "performance-limit-memory-allocation",
			Fn:       CheckMemoryLimit,
			Description: "Verifies containers have memory limits set",
			Remediation: "Set resources.limits.memory on all containers",
			BestPracticeReference: "https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-requests-limits",
			ExceptionProcess: "There is no documented exception process for this.",
			ImpactStatement: PerformanceLimitMemoryAllocationImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "performance-limited-use-of-exec-probes",
			Category: "performance",
			CatalogID: "performance-limited-use-of-exec-probes",
			Fn:       CheckLimitedExecProbes,
			Description: "Verifies cluster-wide exec probe count is below threshold (10)",
			Remediation: "Reduce the number of exec probes or use httpGet/tcpSocket probes",
			BestPracticeReference: "https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cpu-manager-pinning",
			ExceptionProcess: "There is no documented exception process for this.",
			ImpactStatement: PerformanceLimitedUseOfExecProbesImpactStatement,
			Qe: true,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "performance-max-resources-exec-probes",
			Category: "performance",
			CatalogID: "performance-max-resources-exec-probes",
			Fn:       CheckMaxResourcesExecProbes,
			Description: PerformanceMaxResourcesExecProbesDescription,
			Remediation: PerformanceMaxResourcesExecProbesRemediation,
			BestPracticeReference: PerformanceMaxResourcesExecProbesBestPracticeRef,
			ExceptionProcess: PerformanceMaxResourcesExecProbesExceptionProcess,
			ImpactStatement: PerformanceMaxResourcesExecProbesImpactStatement,
			Qe: true,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "performance-rt-apps-no-exec-probes",
			Category: "performance",
			CatalogID: "performance-rt-apps-no-exec-probes",
			Fn:       CheckRTAppsNoExecProbes,
			Description: PerformanceRtAppsNoExecProbesDescription,
			Remediation: PerformanceRtAppsNoExecProbesRemediation,
			BestPracticeReference: PerformanceRtAppsNoExecProbesBestPracticeRef,
			ExceptionProcess: PerformanceRtAppsNoExecProbesExceptionProcess,
			ImpactStatement: PerformanceRtAppsNoExecProbesImpactStatement,
			Qe: true,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "performance-shared-cpu-pool-non-rt-scheduling-policy",
			Category: "performance",
			CatalogID: "shared-cpu-pool-non-rt-scheduling-policy",
			Fn:       CheckSharedCPUPoolSchedulingPolicy,
			Description: PerformanceSharedCpuPoolNonRtSchedulingPolicyDescription,
			Remediation: PerformanceSharedCpuPoolNonRtSchedulingPolicyRemediation,
			BestPracticeReference: PerformanceSharedCpuPoolNonRtSchedulingPolicyBestPracticeRef,
			ExceptionProcess: PerformanceSharedCpuPoolNonRtSchedulingPolicyExceptionProcess,
			ImpactStatement: PerformanceSharedCpuPoolNonRtSchedulingPolicyImpactStatement,
			Qe: true,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})
	})
}
