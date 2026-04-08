package observability

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "observability-compatibility-with-next-ocp-release",
			Category: checks.CategoryObservability,
			CatalogID: "compatibility-with-next-ocp-release",
			Fn:       CheckAPICompatibilityWithNextOCPRelease,
			Description: ObservabilityCompatibilityWithNextOcpReleaseDescription,
			Remediation: ObservabilityCompatibilityWithNextOcpReleaseRemediation,
			BestPracticeReference: ObservabilityCompatibilityWithNextOcpReleaseBestPracticeRef,
			ExceptionProcess: ObservabilityCompatibilityWithNextOcpReleaseExceptionProcess,
			ImpactStatement: ObservabilityCompatibilityWithNextOcpReleaseImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "observability-container-logging",
			Category: checks.CategoryObservability,
			CatalogID: "container-logging",
			Fn:       CheckContainerLogging,
			Description: ObservabilityContainerLoggingDescription,
			Remediation: ObservabilityContainerLoggingRemediation,
			BestPracticeReference: ObservabilityContainerLoggingBestPracticeRef,
			ExceptionProcess: ObservabilityContainerLoggingExceptionProcess,
			ImpactStatement: ObservabilityContainerLoggingImpactStatement,
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
			Name:     "observability-crd-status",
			Category: checks.CategoryObservability,
			CatalogID: "observability-crd-status",
			Fn:       CheckCRDStatus,
			Description: ObservabilityCrdStatusDescription,
			Remediation: ObservabilityCrdStatusRemediation,
			BestPracticeReference: ObservabilityCrdStatusBestPracticeRef,
			ExceptionProcess: ObservabilityCrdStatusExceptionProcess,
			ImpactStatement: ObservabilityCrdStatusImpactStatement,
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
			Name:     "observability-pod-disruption-budget",
			Category: checks.CategoryObservability,
			CatalogID: "observability-pod-disruption-budget",
			Fn:       CheckPodDisruptionBudget,
			Description: ObservabilityPodDisruptionBudgetDescription,
			Remediation: ObservabilityPodDisruptionBudgetRemediation,
			BestPracticeReference: ObservabilityPodDisruptionBudgetBestPracticeRef,
			ExceptionProcess: ObservabilityPodDisruptionBudgetExceptionProcess,
			ImpactStatement: ObservabilityPodDisruptionBudgetImpactStatement,
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
			Name:     "observability-termination-policy",
			Category: checks.CategoryObservability,
			CatalogID: "observability-termination-policy",
			Fn:       CheckTerminationPolicy,
			Description: ObservabilityTerminationPolicyDescription,
			Remediation: ObservabilityTerminationPolicyRemediation,
			BestPracticeReference: ObservabilityTerminationPolicyBestPracticeRef,
			ExceptionProcess: ObservabilityTerminationPolicyExceptionProcess,
			ImpactStatement: ObservabilityTerminationPolicyImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})
	})
}
