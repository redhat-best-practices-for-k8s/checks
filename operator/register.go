package operator

import "github.com/redhat-best-practices-for-k8s/checks"

func init() {
	checks.Register(checks.CheckInfo{
		Name: "operator-install-status-succeeded", Category: "operator",
		Description: "Verifies operator CSVs report Succeeded installation status",
		Remediation: "Ensure operators are properly installed and their CSVs reach Succeeded phase",
		CatalogID:   "operator-install-status-succeeded",
		Fn:          CheckOperatorInstallStatusSucceeded,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-install-status-no-privileges", Category: "operator",
		Description: "Verifies operator CSVs do not grant access to Security Context Constraints",
		Remediation: "Remove SCC-related RBAC rules from operator CSV clusterPermissions",
		CatalogID:   "operator-install-status-no-privileges",
		Fn:          CheckOperatorNoSCCAccess,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-install-source", Category: "operator",
		Description: "Verifies operators are installed via OLM",
		Remediation: "Install operators using Operator Lifecycle Manager (OLM)",
		CatalogID:   "operator-install-source",
		Fn:          CheckOperatorInstalledViaOLM,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-semantic-versioning", Category: "operator",
		Description: "Verifies operator CSVs use valid semantic versioning",
		Remediation: "Use semantic versioning (major.minor.patch) for operator versions",
		CatalogID:   "operator-semantic-versioning",
		Fn:          CheckOperatorSemanticVersioning,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-crd-versioning", Category: "operator",
		Description: "Verifies CRD versions follow Kubernetes versioning conventions",
		Remediation: "Use valid K8s version names (v1, v1alpha1, v1beta1) for CRD versions",
		CatalogID:   "operator-crd-versioning",
		Fn:          CheckCrdVersioning,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-crd-openapi-schema", Category: "operator",
		Description: "Verifies CRDs are defined with OpenAPI v3 schema",
		Remediation: "Add OpenAPI v3 schema validation to CRD spec versions",
		CatalogID:   "operator-crd-openapi-schema",
		Fn:          CheckCrdOpenAPISchema,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-single-crd-owner", Category: "operator",
		Description: "Verifies each CRD is owned by exactly one operator",
		Remediation: "Ensure CRDs are not claimed by multiple operators in their CSV specs",
		CatalogID:   "operator-single-crd-owner",
		Fn:          CheckSingleCrdOwner,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-pods-no-hugepages", Category: "operator",
		Description: "Verifies operator pods do not request hugepages",
		Remediation: "Remove hugepages resource requests from operator pod specifications",
		CatalogID:   "operator-pods-no-hugepages",
		Fn:          CheckOperatorPodsNoHugepages,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-olm-skip-range", Category: "operator",
		Description: "Verifies operator CSVs have olm.skipRange annotation set",
		Remediation: "Add olm.skipRange annotation to CSV metadata for upgrade support",
		CatalogID:   "operator-olm-skip-range",
		Fn:          CheckOperatorOlmSkipRange,
	})
	checks.Register(checks.CheckInfo{
		Name: "operator-multiple-same-operators", Category: "operator",
		Description: "Verifies no operator is installed more than once in the cluster",
		Remediation: "Remove duplicate operator installations so each operator is installed only once",
		CatalogID:   "operator-multiple-same-operators",
		Fn:          CheckMultipleSameOperators,
	})
	checks.Register(checks.CheckInfo{
		Name:        "operator-catalogsource-bundle-count",
		Category:    "operator",
		Description: "Verifies catalog sources have fewer than 1000 bundles",
		Remediation: "Use filtered catalog sources or reduce bundle count",
		CatalogID:   "catalogsource-bundle-count",
		Fn:          CheckCatalogSourceBundleCount,
	})
	checks.Register(checks.CheckInfo{
		Name:        "operator-single-or-multi-namespaced-allowed-in-tenant-namespaces",
		Category:    "operator",
		Description: "Verifies only single/multi namespaced operators in tenant namespaces",
		Remediation: "Use OwnNamespace, SingleNamespace, or MultiNamespace install modes for operators in tenant namespaces",
		CatalogID:   "single-or-multi-namespaced-allowed-in-tenant-namespaces",
		Fn:          CheckSingleOrMultiNamespacedOperators,
	})
}
