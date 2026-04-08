package operator

import "github.com/redhat-best-practices-for-k8s/checks"

// Metadata constants migrated from certsuite identifiers.

// Descriptions
const (
	OperatorCatalogsourceBundleCountDescription = `Tests operator catalog source bundle count is less than 1000`

	OperatorCrdOpenapiSchemaDescription = `Tests whether an application Operator CRD is defined with OpenAPI spec.`

	OperatorCrdVersioningDescription = `Tests whether the Operator CRD has a valid versioning.`

	OperatorInstallSourceDescription = `Tests whether a workload Operator is installed via OLM.`

	OperatorInstallStatusNoPrivilegesDescription = `Checks whether the operator needs access to Security Context Constraints. Test passes if clusterPermissions is not present in the CSV manifest or is present with no RBAC rules related to SCCs.`

	OperatorInstallStatusSucceededDescription = `Ensures that the target workload operators report "Succeeded" as their installation status.`

	OperatorMultipleSameOperatorsDescription = `Tests whether multiple instances of the same Operator CSV are installed.`

	OperatorOlmSkipRangeDescription = `Test that checks the operator has a valid olm skip range.`

	OperatorPodsNoHugepagesDescription = `Tests that the pods do not have hugepages enabled.`

	OperatorSemanticVersioningDescription = `Tests whether an application Operator has a valid semantic versioning.`

	OperatorSingleCrdOwnerDescription = `Tests whether a CRD is owned by a single Operator.`

	OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesDescription = `Verifies that only single/multi namespaced operators are installed in a tenant-dedicated namespace. The test fails if this namespace contains any installed operator with Own/All-namespaced install mode, unlabeled operators, operands of any operator installed elsewhere, or pods unrelated to any operator.`

)

// Remediations
const (
	OperatorCatalogsourceBundleCountRemediation = `Ensure that the Operator's catalog source has a valid bundle count less than 1000.`

	OperatorCrdOpenapiSchemaRemediation = `Ensure that the Operator CRD is defined with OpenAPI spec.`

	OperatorCrdVersioningRemediation = `Ensure that the Operator CRD has a valid version.`

	OperatorInstallSourceRemediation = `Ensure that your Operator is installed via OLM.`

	OperatorInstallStatusNoPrivilegesRemediation = `Ensure all the workload's operators have no privileges on cluster resources.`

	OperatorInstallStatusSucceededRemediation = `Ensure all the workload's operators have been successfully installed by OLM.`

	OperatorMultipleSameOperatorsRemediation = `Ensure that only one Operator of the same type is installed in the cluster.`

	OperatorOlmSkipRangeRemediation = `Ensure that the Operator has a valid OLM skip range. If the operator does not have another version to "skip", then ignore the result of this test.`

	OperatorPodsNoHugepagesRemediation = `Ensure that the pods are not using hugepages`

	OperatorSemanticVersioningRemediation = `Ensure that the Operator has a valid semantic versioning.`

	OperatorSingleCrdOwnerRemediation = `Ensure that a CRD is owned by only one Operator`

	OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesRemediation = `Ensure that operator with install mode SingleNamespaced or MultiNamespaced only is installed in the tenant namespace. Any installed operator with different install mode (AllNamespaced or OwnNamespaced) or pods not belonging to any operator must not be present in this namespace.`

)

// Best practice references
const (
	OperatorCatalogsourceBundleCountBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorCrdOpenapiSchemaBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorCrdVersioningBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorInstallSourceBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorInstallStatusNoPrivilegesBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorInstallStatusSucceededBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorMultipleSameOperatorsBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorOlmSkipRangeBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorPodsNoHugepagesBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorSemanticVersioningBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorSingleCrdOwnerBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

	OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

)

// Exception processes
const (
	OperatorCatalogsourceBundleCountExceptionProcess = checks.NoExceptions

	OperatorCrdOpenapiSchemaExceptionProcess = checks.NoExceptions

	OperatorCrdVersioningExceptionProcess = checks.NoExceptions

	OperatorInstallSourceExceptionProcess = checks.NoExceptions

	OperatorInstallStatusNoPrivilegesExceptionProcess = checks.NoExceptions

	OperatorInstallStatusSucceededExceptionProcess = checks.NoExceptions

	OperatorMultipleSameOperatorsExceptionProcess = checks.NoExceptions

	OperatorOlmSkipRangeExceptionProcess = `If there is not a version of the operator that needs to be skipped, then an exception will be granted.`

	OperatorPodsNoHugepagesExceptionProcess = checks.NoExceptions

	OperatorSemanticVersioningExceptionProcess = checks.NoExceptions

	OperatorSingleCrdOwnerExceptionProcess = checks.NoExceptions

	OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesExceptionProcess = checks.NoExceptions

)

// Impact statements
const (
	OperatorCatalogsourceBundleCountImpactStatement = `Large catalog sources can cause performance issues, slow operator resolution, and increase cluster resource usage.`

	OperatorCrdOpenapiSchemaImpactStatement = `Missing OpenAPI schemas prevent proper validation and can lead to configuration errors and runtime failures.`

	OperatorCrdVersioningImpactStatement = `Invalid CRD versioning can cause API compatibility issues and prevent proper schema evolution.`

	OperatorInstallSourceImpactStatement = `Non-OLM operators bypass lifecycle management and dependency resolution, creating operational complexity and update issues.`

	OperatorInstallStatusNoPrivilegesImpactStatement = `Operators with SCC access have elevated privileges that can compromise cluster security and violate security policies.`

	OperatorInstallStatusSucceededImpactStatement = `Failed operator installations can leave applications in incomplete states, causing functionality gaps and operational issues.`

	OperatorMultipleSameOperatorsImpactStatement = `Multiple operator instances can cause conflicts, resource contention, and unpredictable behavior.`

	OperatorOlmSkipRangeImpactStatement = `Invalid skip ranges can prevent proper operator upgrades and cause version compatibility issues.`

	OperatorPodsNoHugepagesImpactStatement = `Hugepage usage by operators can interfere with application hugepage allocation and cause resource contention.`

	OperatorSemanticVersioningImpactStatement = `Invalid semantic versioning prevents proper upgrade paths and dependency management, causing operational issues.`

	OperatorSingleCrdOwnerImpactStatement = `Multiple CRD owners can cause conflicts, inconsistent behavior, and management complexity.`

	OperatorSingleOrMultiNamespacedAllowedInTenantNamespacesImpactStatement = `Improperly scoped operators can violate tenant isolation and create unauthorized cross-namespace access.`

)
