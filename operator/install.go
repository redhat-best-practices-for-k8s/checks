package operator

import (
	"fmt"

	"github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/redhat-best-practices-for-k8s/checks"
)

// csvCheckFunc is a function that validates a CSV and returns compliance status and message.
type csvCheckFunc func(csv *v1alpha1.ClusterServiceVersion) (compliant bool, message string)

// checkCSVs iterates over CSVs and applies a validation function to each.
func checkCSVs(resources *checks.DiscoveredResources, checkFunc csvCheckFunc, nonCompliantReason string) checks.CheckResult {
	if len(resources.CSVs) == 0 {
		return checks.CheckResult{ComplianceStatus: "Skipped", Reason: "No CSVs found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		compliant, message := checkFunc(csv)
		details = append(details, checks.ResourceDetail{
			Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
			Compliant: compliant, Message: message,
		})
		if !compliant {
			allCompliant = false
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: "Compliant", Details: details}
	}
	return checks.CheckResult{ComplianceStatus: "NonCompliant", Reason: nonCompliantReason, Details: details}
}

// CheckOperatorInstallStatusSucceeded verifies that all CSVs are in Succeeded phase.
func CheckOperatorInstallStatusSucceeded(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkCSVs(resources, func(csv *v1alpha1.ClusterServiceVersion) (bool, string) {
		phase := csv.Status.Phase
		if phase == v1alpha1.CSVPhaseSucceeded {
			return true, "CSV in Succeeded phase"
		}
		return false, fmt.Sprintf("CSV in %s phase, expected Succeeded", phase)
	}, "One or more CSVs not in Succeeded phase")
}

// CheckOperatorInstalledViaOLM verifies that CSVs have a subscription (installed via OLM).
// It checks if the "operatorframework.io/properties" annotation exists on the CSV,
// which indicates OLM management. For the shared library, we check if the CSV has
// the subscription label set by OLM.
func CheckOperatorInstalledViaOLM(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkCSVs(resources, func(csv *v1alpha1.ClusterServiceVersion) (bool, string) {
		// OLM-installed operators have the olm.operatorNamespace annotation
		if _, hasOLMAnnotation := csv.Annotations["olm.operatorNamespace"]; hasOLMAnnotation {
			return true, "Operator installed via OLM"
		}
		return false, "Operator not installed via OLM (missing olm.operatorNamespace annotation)"
	}, "One or more operators not installed via OLM")
}

// CheckOperatorOlmSkipRange verifies that CSVs have olm.skipRange annotation set.
func CheckOperatorOlmSkipRange(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkCSVs(resources, func(csv *v1alpha1.ClusterServiceVersion) (bool, string) {
		skipRange := csv.Annotations["olm.skipRange"]
		if skipRange != "" {
			return true, fmt.Sprintf("olm.skipRange set: %s", skipRange)
		}
		return false, "olm.skipRange annotation not set"
	}, "One or more CSVs missing olm.skipRange")
}
