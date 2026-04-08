package operator

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "operator-catalogsource-bundle-count",
			Category: checks.CategoryOperator,
			CatalogID: "catalogsource-bundle-count",
			Fn:       CheckCatalogSourceBundleCount,
			Description: OperatorCatalogsourceBundleCountDescription,
			Remediation: OperatorCatalogsourceBundleCountRemediation,
			BestPracticeReference: OperatorCatalogsourceBundleCountBestPracticeRef,
			ExceptionProcess: OperatorCatalogsourceBundleCountExceptionProcess,
			ImpactStatement: OperatorCatalogsourceBundleCountImpactStatement,
			Qe: false,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "operator-crd-openapi-schema",
			Category: checks.CategoryOperator,
			CatalogID: "operator-crd-openapi-schema",
			Fn:       CheckCrdOpenAPISchema,
			Description: OperatorCrdOpenapiSchemaDescription,
			Remediation: OperatorCrdOpenapiSchemaRemediation,
			BestPracticeReference: OperatorCrdOpenapiSchemaBestPracticeRef,
			ExceptionProcess: OperatorCrdOpenapiSchemaExceptionProcess,
			ImpactStatement: OperatorCrdOpenapiSchemaImpactStatement,
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
			Name:     "operator-crd-versioning",
			Category: checks.CategoryOperator,
			CatalogID: "operator-crd-versioning",
			Fn:       CheckCrdVersioning,
			Description: OperatorCrdVersioningDescription,
			Remediation: OperatorCrdVersioningRemediation,
			BestPracticeReference: OperatorCrdVersioningBestPracticeRef,
			ExceptionProcess: OperatorCrdVersioningExceptionProcess,
			ImpactStatement: OperatorCrdVersioningImpactStatement,
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
			Name:     "operator-install-source",
			Category: checks.CategoryOperator,
			CatalogID: "operator-install-source",
			Fn:       CheckOperatorInstalledViaOLM,
			Description: OperatorInstallSourceDescription,
			Remediation: OperatorInstallSourceRemediation,
			BestPracticeReference: OperatorInstallSourceBestPracticeRef,
			ExceptionProcess: OperatorInstallSourceExceptionProcess,
			ImpactStatement: OperatorInstallSourceImpactStatement,
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
			Name:     "operator-install-status-no-privileges",
			Category: checks.CategoryOperator,
			CatalogID: "operator-install-status-no-privileges",
			Fn:       CheckOperatorNoSCCAccess,
			Description: OperatorInstallStatusNoPrivilegesDescription,
			Remediation: OperatorInstallStatusNoPrivilegesRemediation,
			BestPracticeReference: OperatorInstallStatusNoPrivilegesBestPracticeRef,
			ExceptionProcess: OperatorInstallStatusNoPrivilegesExceptionProcess,
			ImpactStatement: OperatorInstallStatusNoPrivilegesImpactStatement,
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
			Name:     "operator-install-status-succeeded",
			Category: checks.CategoryOperator,
			CatalogID: "operator-install-status-succeeded",
			Fn:       CheckOperatorInstallStatusSucceeded,
			Description: OperatorInstallStatusSucceededDescription,
			Remediation: OperatorInstallStatusSucceededRemediation,
			BestPracticeReference: OperatorInstallStatusSucceededBestPracticeRef,
			ExceptionProcess: OperatorInstallStatusSucceededExceptionProcess,
			ImpactStatement: OperatorInstallStatusSucceededImpactStatement,
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
			Name:     "operator-multiple-same-operators",
			Category: checks.CategoryOperator,
			CatalogID: "operator-multiple-same-operators",
			Fn:       CheckMultipleSameOperators,
			Description: OperatorMultipleSameOperatorsDescription,
			Remediation: OperatorMultipleSameOperatorsRemediation,
			BestPracticeReference: OperatorMultipleSameOperatorsBestPracticeRef,
			ExceptionProcess: OperatorMultipleSameOperatorsExceptionProcess,
			ImpactStatement: OperatorMultipleSameOperatorsImpactStatement,
			Qe: false,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "operator-olm-skip-range",
			Category: checks.CategoryOperator,
			CatalogID: "operator-olm-skip-range",
			Fn:       CheckOperatorOlmSkipRange,
			Description: OperatorOlmSkipRangeDescription,
			Remediation: OperatorOlmSkipRangeRemediation,
			BestPracticeReference: OperatorOlmSkipRangeBestPracticeRef,
			ExceptionProcess: OperatorOlmSkipRangeExceptionProcess,
			ImpactStatement: OperatorOlmSkipRangeImpactStatement,
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
			Name:     "operator-pods-no-hugepages",
			Category: checks.CategoryOperator,
			CatalogID: "operator-pods-no-hugepages",
			Fn:       CheckOperatorPodsNoHugepages,
			Description: OperatorPodsNoHugepagesDescription,
			Remediation: OperatorPodsNoHugepagesRemediation,
			BestPracticeReference: OperatorPodsNoHugepagesBestPracticeRef,
			ExceptionProcess: OperatorPodsNoHugepagesExceptionProcess,
			ImpactStatement: OperatorPodsNoHugepagesImpactStatement,
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
			Name:     "operator-semantic-versioning",
			Category: checks.CategoryOperator,
			CatalogID: "operator-semantic-versioning",
			Fn:       CheckOperatorSemanticVersioning,
			Description: OperatorSemanticVersioningDescription,
			Remediation: OperatorSemanticVersioningRemediation,
			BestPracticeReference: OperatorSemanticVersioningBestPracticeRef,
			ExceptionProcess: OperatorSemanticVersioningExceptionProcess,
			ImpactStatement: OperatorSemanticVersioningImpactStatement,
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
			Name:     "operator-single-crd-owner",
			Category: checks.CategoryOperator,
			CatalogID: "operator-single-crd-owner",
			Fn:       CheckSingleCrdOwner,
			Description: OperatorSingleCrdOwnerDescription,
			Remediation: OperatorSingleCrdOwnerRemediation,
			BestPracticeReference: OperatorSingleCrdOwnerBestPracticeRef,
			ExceptionProcess: OperatorSingleCrdOwnerExceptionProcess,
			ImpactStatement: OperatorSingleCrdOwnerImpactStatement,
			Qe: false,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "operator-single-or-multi-namespaced-allowed-in-tenant-namespaces",
			Category: checks.CategoryOperator,
			CatalogID: "single-or-multi-namespaced-allowed-in-tenant-namespaces",
			Fn:       CheckSingleOrMultiNamespacedOperators,
			Description: OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesDescription,
			Remediation: OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesRemediation,
			BestPracticeReference: OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesBestPracticeRef,
			ExceptionProcess: OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesExceptionProcess,
			ImpactStatement: OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})
	})
}
