package lifecycle

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "lifecycle-affinity-required-pods",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-affinity-required-pods",
			Fn:       CheckAffinityRequired,
			Description: LifecycleAffinityRequiredPodsDescription,
			Remediation: LifecycleAffinityRequiredPodsRemediation,
			BestPracticeReference: LifecycleAffinityRequiredPodsBestPracticeRef,
			ExceptionProcess: LifecycleAffinityRequiredPodsExceptionProcess,
			ImpactStatement: LifecycleAffinityRequiredPodsImpactStatement,
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
			Name:     "lifecycle-container-poststart",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-container-poststart",
			Fn:       CheckPostStart,
			Description: LifecycleContainerPoststartDescription,
			Remediation: LifecycleContainerPoststartRemediation,
			BestPracticeReference: LifecycleContainerPoststartBestPracticeRef,
			ExceptionProcess: LifecycleContainerPoststartExceptionProcess,
			ImpactStatement: LifecycleContainerPoststartImpactStatement,
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
			Name:     "lifecycle-container-prestop",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-container-prestop",
			Fn:       CheckPreStop,
			Description: LifecycleContainerPrestopDescription,
			Remediation: LifecycleContainerPrestopRemediation,
			BestPracticeReference: LifecycleContainerPrestopBestPracticeRef,
			ExceptionProcess: LifecycleContainerPrestopExceptionProcess,
			ImpactStatement: LifecycleContainerPrestopImpactStatement,
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
			Name:     "lifecycle-cpu-isolation",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-cpu-isolation",
			Fn:       CheckCPUIsolation,
			Description: LifecycleCpuIsolationDescription,
			Remediation: LifecycleCpuIsolationRemediation,
			BestPracticeReference: LifecycleCpuIsolationBestPracticeRef,
			ExceptionProcess: LifecycleCpuIsolationExceptionProcess,
			ImpactStatement: LifecycleCpuIsolationImpactStatement,
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
			Name:     "lifecycle-crd-scaling",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-crd-scaling",
			Fn:       CheckCRDScaling,
			Description: LifecycleCrdScalingDescription,
			Remediation: LifecycleCrdScalingRemediation,
			BestPracticeReference: LifecycleCrdScalingBestPracticeRef,
			ExceptionProcess: LifecycleCrdScalingExceptionProcess,
			ImpactStatement: LifecycleCrdScalingImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "lifecycle-deployment-scaling",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-deployment-scaling",
			Fn:       CheckDeploymentScaling,
			Description: LifecycleDeploymentScalingDescription,
			Remediation: LifecycleDeploymentScalingRemediation,
			BestPracticeReference: LifecycleDeploymentScalingBestPracticeRef,
			ExceptionProcess: LifecycleDeploymentScalingExceptionProcess,
			ImpactStatement: LifecycleDeploymentScalingImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "lifecycle-image-pull-policy",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-image-pull-policy",
			Fn:       CheckImagePullPolicy,
			Description: LifecycleImagePullPolicyDescription,
			Remediation: LifecycleImagePullPolicyRemediation,
			BestPracticeReference: LifecycleImagePullPolicyBestPracticeRef,
			ExceptionProcess: LifecycleImagePullPolicyExceptionProcess,
			ImpactStatement: LifecycleImagePullPolicyImpactStatement,
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
			Name:     "lifecycle-liveness-probe",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-liveness-probe",
			Fn:       CheckLivenessProbe,
			Description: LifecycleLivenessProbeDescription,
			Remediation: LifecycleLivenessProbeRemediation,
			BestPracticeReference: LifecycleLivenessProbeBestPracticeRef,
			ExceptionProcess: LifecycleLivenessProbeExceptionProcess,
			ImpactStatement: LifecycleLivenessProbeImpactStatement,
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
			Name:     "lifecycle-persistent-volume-reclaim-policy",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-persistent-volume-reclaim-policy",
			Fn:       CheckPVReclaimPolicy,
			Description: LifecyclePersistentVolumeReclaimPolicyDescription,
			Remediation: LifecyclePersistentVolumeReclaimPolicyRemediation,
			BestPracticeReference: LifecyclePersistentVolumeReclaimPolicyBestPracticeRef,
			ExceptionProcess: LifecyclePersistentVolumeReclaimPolicyExceptionProcess,
			ImpactStatement: LifecyclePersistentVolumeReclaimPolicyImpactStatement,
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
			Name:     "lifecycle-pod-high-availability",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-pod-high-availability",
			Fn:       CheckHighAvailability,
			Description: LifecyclePodHighAvailabilityDescription,
			Remediation: LifecyclePodHighAvailabilityRemediation,
			BestPracticeReference: LifecyclePodHighAvailabilityBestPracticeRef,
			ExceptionProcess: LifecyclePodHighAvailabilityExceptionProcess,
			ImpactStatement: LifecyclePodHighAvailabilityImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "lifecycle-pod-owner-type",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-pod-owner-type",
			Fn:       CheckPodOwnerType,
			Description: LifecyclePodOwnerTypeDescription,
			Remediation: LifecyclePodOwnerTypeRemediation,
			BestPracticeReference: LifecyclePodOwnerTypeBestPracticeRef,
			ExceptionProcess: LifecyclePodOwnerTypeExceptionProcess,
			ImpactStatement: LifecyclePodOwnerTypeImpactStatement,
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
			Name:     "lifecycle-pod-recreation",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-pod-recreation",
			Fn:       CheckPodRecreation,
			Description: LifecyclePodRecreationDescription,
			Remediation: LifecyclePodRecreationRemediation,
			BestPracticeReference: LifecyclePodRecreationBestPracticeRef,
			ExceptionProcess: LifecyclePodRecreationExceptionProcess,
			ImpactStatement: LifecyclePodRecreationImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "lifecycle-pod-scheduling",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-pod-scheduling",
			Fn:       CheckPodScheduling,
			Description: LifecyclePodSchedulingDescription,
			Remediation: LifecyclePodSchedulingRemediation,
			BestPracticeReference: LifecyclePodSchedulingBestPracticeRef,
			ExceptionProcess: LifecyclePodSchedulingExceptionProcess,
			ImpactStatement: LifecyclePodSchedulingImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "lifecycle-pod-toleration-bypass",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-pod-toleration-bypass",
			Fn:       CheckTolerationBypass,
			Description: LifecyclePodTolerationBypassDescription,
			Remediation: LifecyclePodTolerationBypassRemediation,
			BestPracticeReference: LifecyclePodTolerationBypassBestPracticeRef,
			ExceptionProcess: LifecyclePodTolerationBypassExceptionProcess,
			ImpactStatement: LifecyclePodTolerationBypassImpactStatement,
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
			Name:     "lifecycle-readiness-probe",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-readiness-probe",
			Fn:       CheckReadinessProbe,
			Description: LifecycleReadinessProbeDescription,
			Remediation: LifecycleReadinessProbeRemediation,
			BestPracticeReference: LifecycleReadinessProbeBestPracticeRef,
			ExceptionProcess: LifecycleReadinessProbeExceptionProcess,
			ImpactStatement: LifecycleReadinessProbeImpactStatement,
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
			Name:     "lifecycle-startup-probe",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-startup-probe",
			Fn:       CheckStartupProbe,
			Description: LifecycleStartupProbeDescription,
			Remediation: LifecycleStartupProbeRemediation,
			BestPracticeReference: LifecycleStartupProbeBestPracticeRef,
			ExceptionProcess: LifecycleStartupProbeExceptionProcess,
			ImpactStatement: LifecycleStartupProbeImpactStatement,
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
			Name:     "lifecycle-statefulset-scaling",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-statefulset-scaling",
			Fn:       CheckStatefulSetScaling,
			Description: LifecycleStatefulsetScalingDescription,
			Remediation: LifecycleStatefulsetScalingRemediation,
			BestPracticeReference: LifecycleStatefulsetScalingBestPracticeRef,
			ExceptionProcess: LifecycleStatefulsetScalingExceptionProcess,
			ImpactStatement: LifecycleStatefulsetScalingImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "lifecycle-storage-provisioner",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-storage-provisioner",
			Fn:       CheckStorageProvisioner,
			Description: LifecycleStorageProvisionerDescription,
			Remediation: LifecycleStorageProvisionerRemediation,
			BestPracticeReference: LifecycleStorageProvisionerBestPracticeRef,
			ExceptionProcess: LifecycleStorageProvisionerExceptionProcess,
			ImpactStatement: LifecycleStorageProvisionerImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "lifecycle-topology-spread-constraint",
			Category: checks.CategoryLifecycle,
			CatalogID: "lifecycle-topology-spread-constraint",
			Fn:       CheckTopologySpreadConstraints,
			Description: LifecycleTopologySpreadConstraintDescription,
			Remediation: LifecycleTopologySpreadConstraintRemediation,
			BestPracticeReference: LifecycleTopologySpreadConstraintBestPracticeRef,
			ExceptionProcess: LifecycleTopologySpreadConstraintExceptionProcess,
			ImpactStatement: LifecycleTopologySpreadConstraintImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})
	})
}
