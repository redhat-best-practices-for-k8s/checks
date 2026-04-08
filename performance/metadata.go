package performance

import "github.com/redhat-best-practices-for-k8s/checks"

// Metadata constants migrated from certsuite identifiers.

// Descriptions
const (
	PerformanceCpuPinningNoExecProbesDescription = `Workloads utilizing CPU pinning (Guaranteed QoS with exclusive CPUs) should not use exec probes. Exec probes run a command within the container, which could interfere with latency-sensitive workloads and cause performance degradation.`

	PerformanceExclusiveCpuPoolDescription = `Ensures that if one container in a Pod selects an exclusive CPU pool the rest select the same type of CPU pool`

	PerformanceExclusiveCpuPoolRtSchedulingPolicyDescription = `Ensures that if application workload runs in exclusive CPU pool, it chooses RT CPU schedule policy and set the priority less than 10.`

	PerformanceIsolatedCpuPoolRtSchedulingPolicyDescription = `Ensures that a workload running in an application-isolated exclusive CPU pool selects a RT CPU scheduling policy`

	PerformanceLimitMemoryAllocationDescription = `Verifies containers have memory limits set`

	PerformanceLimitedUseOfExecProbesDescription = `Verifies cluster-wide exec probe count is below threshold (10)`

	PerformanceMaxResourcesExecProbesDescription = `Checks that less than 10 exec probes are configured in the cluster for this workload. Also checks that the periodSeconds parameter for each probe is superior or equal to 10.`

	PerformanceRtAppsNoExecProbesDescription = `Ensures that if one container runs a real time application exec probes are not used`

	PerformanceSharedCpuPoolNonRtSchedulingPolicyDescription = `Ensures that if application workload runs in shared CPU pool, it chooses non-RT CPU schedule policy to always share the CPU with other applications and kernel threads.`

)

// Remediations
const (
	PerformanceCpuPinningNoExecProbesRemediation = `Workloads that use CPU pinning (Guaranteed QoS with exclusive CPUs) should not use exec probes. Use httpGet or tcpSocket probes instead, as exec probes can interfere with latency-sensitive workloads requiring non-interruptible task execution.`

	PerformanceExclusiveCpuPoolRemediation = `Ensure that if one container in a Pod selects an exclusive CPU pool the rest also select this type of CPU pool`

	PerformanceExclusiveCpuPoolRtSchedulingPolicyRemediation = `Ensure that the workload running in Application exclusive CPU pool can choose RT CPU scheduling policy, but should set priority less than 10`

	PerformanceIsolatedCpuPoolRtSchedulingPolicyRemediation = `Ensure that the workload running in an application-isolated exclusive CPU pool selects a RT CPU scheduling policy (such as SCHED_FIFO/SCHED_RR) with High priority.`

	PerformanceLimitMemoryAllocationRemediation = `Set resources.limits.memory on all containers`

	PerformanceLimitedUseOfExecProbesRemediation = `Reduce the number of exec probes or use httpGet/tcpSocket probes`

	PerformanceMaxResourcesExecProbesRemediation = `Reduce the number of exec probes in the cluster for this workload to less than 10. Increase the update period of the exec probe to be superior or equal to 10 seconds.`

	PerformanceRtAppsNoExecProbesRemediation = `Ensure that if one container runs a real time application exec probes are not used`

	PerformanceSharedCpuPoolNonRtSchedulingPolicyRemediation = `Ensure that the workload running in Application shared CPU pool should choose non-RT CPU schedule policy, like SCHED _OTHER to always share the CPU with other applications and kernel threads.`

)

// Best practice references
const (
	PerformanceCpuPinningNoExecProbesBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cpu-manager-pinning`

	PerformanceExclusiveCpuPoolBestPracticeRef = checks.NoDocLinkFarEdge

	PerformanceExclusiveCpuPoolRtSchedulingPolicyBestPracticeRef = checks.NoDocLinkFarEdge

	PerformanceIsolatedCpuPoolRtSchedulingPolicyBestPracticeRef = checks.NoDocLinkFarEdge

	PerformanceLimitMemoryAllocationBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-requests-limits`

	PerformanceLimitedUseOfExecProbesBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cpu-manager-pinning`

	PerformanceMaxResourcesExecProbesBestPracticeRef = checks.NoDocLinkFarEdge

	PerformanceRtAppsNoExecProbesBestPracticeRef = checks.NoDocLinkFarEdge

	PerformanceSharedCpuPoolNonRtSchedulingPolicyBestPracticeRef = checks.NoDocLinkFarEdge

)

// Exception processes
const (
	PerformanceCpuPinningNoExecProbesExceptionProcess = checks.NoExceptionProcess

	PerformanceExclusiveCpuPoolExceptionProcess = checks.NoExceptionProcess

	PerformanceExclusiveCpuPoolRtSchedulingPolicyExceptionProcess = checks.NoExceptionProcess

	PerformanceIsolatedCpuPoolRtSchedulingPolicyExceptionProcess = checks.NoExceptionProcess

	PerformanceLimitMemoryAllocationExceptionProcess = checks.NoExceptionProcess

	PerformanceLimitedUseOfExecProbesExceptionProcess = checks.NoExceptionProcess

	PerformanceMaxResourcesExecProbesExceptionProcess = checks.NoExceptionProcess

	PerformanceRtAppsNoExecProbesExceptionProcess = checks.NoExceptionProcess

	PerformanceSharedCpuPoolNonRtSchedulingPolicyExceptionProcess = checks.NoExceptionProcess

)

// Impact statements
const (
	PerformanceCpuPinningNoExecProbesImpactStatement = `Exec probes on workloads with CPU pinning (exclusive CPUs) can cause performance degradation, interrupt latency-sensitive operations, and potentially crash applications due to resource contention. Any workload requiring exclusive CPUs inherently needs non-interruptible task execution.`

	PerformanceExclusiveCpuPoolImpactStatement = `Inconsistent CPU pool selection can cause performance interference and unpredictable latency in real-time applications.`

	PerformanceExclusiveCpuPoolRtSchedulingPolicyImpactStatement = `Wrong scheduling policies in exclusive CPU pools can prevent real-time applications from meeting latency requirements.`

	PerformanceIsolatedCpuPoolRtSchedulingPolicyImpactStatement = `Incorrect scheduling policies in isolated CPU pools can cause performance degradation and violate real-time guarantees.`

	PerformanceLimitMemoryAllocationImpactStatement = `Missing memory limits can lead to uncontrolled memory consumption, out-of-memory kills, and node instability affecting other workloads.`

	PerformanceLimitedUseOfExecProbesImpactStatement = `Excessive exec probes can overwhelm system resources, degrade performance, and interfere with critical application operations in resource-constrained environments.`

	PerformanceMaxResourcesExecProbesImpactStatement = `Excessive exec probes can overwhelm system resources, degrade performance, and interfere with critical application operations in resource-constrained environments.`

	PerformanceRtAppsNoExecProbesImpactStatement = `Exec probes on real-time applications can cause latency spikes and interrupt time-critical operations.`

	PerformanceSharedCpuPoolNonRtSchedulingPolicyImpactStatement = `Incorrect scheduling policies in shared CPU pools can cause performance interference and unfair resource distribution.`

)
