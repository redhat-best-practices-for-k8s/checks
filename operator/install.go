package operator

import (
	"fmt"

	"github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckOperatorInstallStatusSucceeded verifies that all CSVs are in Succeeded phase.
func CheckOperatorInstallStatusSucceeded(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.CSVs) == 0 {
		return checks.CheckResult{ComplianceStatus: "Skipped", Reason: "No CSVs found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		phase := csv.Status.Phase
		if phase == v1alpha1.CSVPhaseSucceeded {
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: true, Message: "CSV in Succeeded phase",
			})
		} else {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: false, Message: fmt.Sprintf("CSV in %s phase, expected Succeeded", phase),
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: "Compliant", Details: details}
	}
	return checks.CheckResult{ComplianceStatus: "NonCompliant", Reason: "One or more CSVs not in Succeeded phase", Details: details}
}

// CheckOperatorInstalledViaOLM verifies that CSVs have a subscription (installed via OLM).
// It checks if the "operatorframework.io/properties" annotation exists on the CSV,
// which indicates OLM management. For the shared library, we check if the CSV has
// the subscription label set by OLM.
func CheckOperatorInstalledViaOLM(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.CSVs) == 0 {
		return checks.CheckResult{ComplianceStatus: "Skipped", Reason: "No CSVs found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		// OLM-installed operators have the olm.operatorNamespace annotation
		if _, hasOLMAnnotation := csv.Annotations["olm.operatorNamespace"]; hasOLMAnnotation {
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: true, Message: "Operator installed via OLM",
			})
		} else {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: false, Message: "Operator not installed via OLM (missing olm.operatorNamespace annotation)",
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: "Compliant", Details: details}
	}
	return checks.CheckResult{ComplianceStatus: "NonCompliant", Reason: "One or more operators not installed via OLM", Details: details}
}

// CheckOperatorOlmSkipRange verifies that CSVs have olm.skipRange annotation set.
func CheckOperatorOlmSkipRange(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.CSVs) == 0 {
		return checks.CheckResult{ComplianceStatus: "Skipped", Reason: "No CSVs found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		skipRange := csv.Annotations["olm.skipRange"]
		if skipRange != "" {
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: true, Message: fmt.Sprintf("olm.skipRange set: %s", skipRange),
			})
		} else {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: false, Message: "olm.skipRange annotation not set",
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: "Compliant", Details: details}
	}
	return checks.CheckResult{ComplianceStatus: "NonCompliant", Reason: "One or more CSVs missing olm.skipRange", Details: details}
}
