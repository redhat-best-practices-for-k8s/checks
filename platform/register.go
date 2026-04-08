package platform

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "platform-alteration-base-image",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "base-image",
			Fn:       CheckUnalteredBaseImage,
			Description: PlatformAlterationBaseImageDescription,
			Remediation: PlatformAlterationBaseImageRemediation,
			BestPracticeReference: PlatformAlterationBaseImageBestPracticeRef,
			ExceptionProcess: PlatformAlterationBaseImageExceptionProcess,
			ImpactStatement: PlatformAlterationBaseImageImpactStatement,
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
			Name:     "platform-alteration-boot-params",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-boot-params",
			Fn:       CheckBootParams,
			Description: PlatformAlterationBootParamsDescription,
			Remediation: PlatformAlterationBootParamsRemediation,
			BestPracticeReference: PlatformAlterationBootParamsBestPracticeRef,
			ExceptionProcess: PlatformAlterationBootParamsExceptionProcess,
			ImpactStatement: PlatformAlterationBootParamsImpactStatement,
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
			Name:     "platform-alteration-cluster-operator-health",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "cluster-operator-health",
			Fn:       CheckClusterOperatorHealth,
			Description: PlatformAlterationClusterOperatorHealthDescription,
			Remediation: PlatformAlterationClusterOperatorHealthRemediation,
			BestPracticeReference: PlatformAlterationClusterOperatorHealthBestPracticeRef,
			ExceptionProcess: PlatformAlterationClusterOperatorHealthExceptionProcess,
			ImpactStatement: PlatformAlterationClusterOperatorHealthImpactStatement,
			Qe: false,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "platform-alteration-hugepages-1g-only",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-hugepages-1g-only",
			Fn:       CheckHugepages1GiOnly,
			Description: PlatformAlterationHugepages1gOnlyDescription,
			Remediation: PlatformAlterationHugepages1gOnlyRemediation,
			BestPracticeReference: PlatformAlterationHugepages1gOnlyBestPracticeRef,
			ExceptionProcess: PlatformAlterationHugepages1gOnlyExceptionProcess,
			ImpactStatement: PlatformAlterationHugepages1gOnlyImpactStatement,
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
			Name:     "platform-alteration-hugepages-2m-only",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-hugepages-2m-only",
			Fn:       CheckHugepages2MiOnly,
			Description: PlatformAlterationHugepages2mOnlyDescription,
			Remediation: PlatformAlterationHugepages2mOnlyRemediation,
			BestPracticeReference: PlatformAlterationHugepages2mOnlyBestPracticeRef,
			ExceptionProcess: PlatformAlterationHugepages2mOnlyExceptionProcess,
			ImpactStatement: PlatformAlterationHugepages2mOnlyImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "platform-alteration-hugepages-config",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-hugepages-config",
			Fn:       CheckHugepages,
			Description: PlatformAlterationHugepagesConfigDescription,
			Remediation: PlatformAlterationHugepagesConfigRemediation,
			BestPracticeReference: PlatformAlterationHugepagesConfigBestPracticeRef,
			ExceptionProcess: PlatformAlterationHugepagesConfigExceptionProcess,
			ImpactStatement: PlatformAlterationHugepagesConfigImpactStatement,
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
			Name:     "platform-alteration-hyperthread-enable",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "hyperthread-enable",
			Fn:       CheckHyperthreadEnable,
			Description: PlatformAlterationHyperthreadEnableDescription,
			Remediation: PlatformAlterationHyperthreadEnableRemediation,
			BestPracticeReference: PlatformAlterationHyperthreadEnableBestPracticeRef,
			ExceptionProcess: PlatformAlterationHyperthreadEnableExceptionProcess,
			ImpactStatement: PlatformAlterationHyperthreadEnableImpactStatement,
			Qe: false,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "platform-alteration-is-selinux-enforcing",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-is-selinux-enforcing",
			Fn:       CheckSELinuxEnforcing,
			Description: PlatformAlterationIsSelinuxEnforcingDescription,
			Remediation: PlatformAlterationIsSelinuxEnforcingRemediation,
			BestPracticeReference: PlatformAlterationIsSelinuxEnforcingBestPracticeRef,
			ExceptionProcess: PlatformAlterationIsSelinuxEnforcingExceptionProcess,
			ImpactStatement: PlatformAlterationIsSelinuxEnforcingImpactStatement,
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
			Name:     "platform-alteration-isredhat-release",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "isredhat-release",
			Fn:       CheckIsRedHatRelease,
			Description: PlatformAlterationIsredhatReleaseDescription,
			Remediation: PlatformAlterationIsredhatReleaseRemediation,
			BestPracticeReference: PlatformAlterationIsredhatReleaseBestPracticeRef,
			ExceptionProcess: PlatformAlterationIsredhatReleaseExceptionProcess,
			ImpactStatement: PlatformAlterationIsredhatReleaseImpactStatement,
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
			Name:     "platform-alteration-ocp-lifecycle",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "ocp-lifecycle",
			Fn:       CheckOCPLifecycle,
			Description: PlatformAlterationOcpLifecycleDescription,
			Remediation: PlatformAlterationOcpLifecycleRemediation,
			BestPracticeReference: PlatformAlterationOcpLifecycleBestPracticeRef,
			ExceptionProcess: PlatformAlterationOcpLifecycleExceptionProcess,
			ImpactStatement: PlatformAlterationOcpLifecycleImpactStatement,
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
			Name:     "platform-alteration-ocp-node-count",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-ocp-node-count",
			Fn:       CheckNodeCount,
			Description: PlatformAlterationOcpNodeCountDescription,
			Remediation: PlatformAlterationOcpNodeCountRemediation,
			BestPracticeReference: PlatformAlterationOcpNodeCountBestPracticeRef,
			ExceptionProcess: PlatformAlterationOcpNodeCountExceptionProcess,
			ImpactStatement: PlatformAlterationOcpNodeCountImpactStatement,
			Qe: false,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "platform-alteration-ocp-node-os-lifecycle",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "ocp-node-os-lifecycle",
			Fn:       CheckOCPNodeOSLifecycle,
			Description: PlatformAlterationOcpNodeOsLifecycleDescription,
			Remediation: PlatformAlterationOcpNodeOsLifecycleRemediation,
			BestPracticeReference: PlatformAlterationOcpNodeOsLifecycleBestPracticeRef,
			ExceptionProcess: PlatformAlterationOcpNodeOsLifecycleExceptionProcess,
			ImpactStatement: PlatformAlterationOcpNodeOsLifecycleImpactStatement,
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
			Name:     "platform-alteration-service-mesh-usage",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-service-mesh-usage",
			Fn:       CheckServiceMeshUsage,
			Description: PlatformAlterationServiceMeshUsageDescription,
			Remediation: PlatformAlterationServiceMeshUsageRemediation,
			BestPracticeReference: PlatformAlterationServiceMeshUsageBestPracticeRef,
			ExceptionProcess: PlatformAlterationServiceMeshUsageExceptionProcess,
			ImpactStatement: PlatformAlterationServiceMeshUsageImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "platform-alteration-sysctl-config",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-sysctl-config",
			Fn:       CheckSysctl,
			Description: PlatformAlterationSysctlConfigDescription,
			Remediation: PlatformAlterationSysctlConfigRemediation,
			BestPracticeReference: PlatformAlterationSysctlConfigBestPracticeRef,
			ExceptionProcess: PlatformAlterationSysctlConfigExceptionProcess,
			ImpactStatement: PlatformAlterationSysctlConfigImpactStatement,
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
			Name:     "platform-alteration-tainted-node-kernel",
			Category: checks.CategoryPlatformAlteration,
			CatalogID: "platform-alteration-tainted-node-kernel",
			Fn:       CheckTainted,
			Description: PlatformAlterationTaintedNodeKernelDescription,
			Remediation: PlatformAlterationTaintedNodeKernelRemediation,
			BestPracticeReference: PlatformAlterationTaintedNodeKernelBestPracticeRef,
			ExceptionProcess: PlatformAlterationTaintedNodeKernelExceptionProcess,
			ImpactStatement: PlatformAlterationTaintedNodeKernelImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})
	})
}
