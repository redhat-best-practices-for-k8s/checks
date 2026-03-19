package operator

import (
	"fmt"
	"strings"

	olmv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckSingleOrMultiNamespacedOperators verifies only single/multi namespaced operators
// are installed in tenant-dedicated namespaces.
func CheckSingleOrMultiNamespacedOperators(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if len(resources.CSVs) == 0 {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "No operators found"
		return result
	}

	// Group operators by install namespace
	operatorsByNamespace := make(map[string][]olmv1alpha1.ClusterServiceVersion)
	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		installNs := csv.Annotations["olm.operatorNamespace"]
		if installNs == "" {
			installNs = csv.Namespace
		}

		// Only check namespaces that are in our target list
		if isTargetNamespace(installNs, resources.Namespaces) {
			operatorsByNamespace[installNs] = append(operatorsByNamespace[installNs], *csv)
		}
	}

	for namespace, csvs := range operatorsByNamespace {
		var singleMultiOps []string
		var otherModeOps []string

		for i := range csvs {
			csv := &csvs[i]
			installMode := getInstallMode(csv)

			if installMode == "OwnNamespace" || installMode == "SingleNamespace" || installMode == "MultiNamespace" {
				singleMultiOps = append(singleMultiOps, csv.Name)
			} else {
				otherModeOps = append(otherModeOps, csv.Name)
			}
		}

		isDedicated := len(otherModeOps) == 0

		if isDedicated {
			var msg string
			if len(singleMultiOps) == 0 {
				msg = "Namespace contains no installed single/multi namespace operators"
			} else {
				msg = fmt.Sprintf("Namespace is dedicated to single/multi namespace operators (%s)", strings.Join(singleMultiOps, ", "))
			}
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Namespace",
				Name:      namespace,
				Compliant: true,
				Message:   msg,
			})
		} else {
			msg := fmt.Sprintf("Namespace is not dedicated to single/multi operators: operators with other install modes found (%s)",
				strings.Join(otherModeOps, ", "))
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Namespace",
				Name:      namespace,
				Compliant: false,
				Message:   msg,
			})
			result.ComplianceStatus = checks.StatusNonCompliant
			result.Reason = "One or more namespaces contain operators with AllNamespaces install mode"
		}
	}

	return result
}

func getInstallMode(csv *olmv1alpha1.ClusterServiceVersion) string {
	if csv.Spec.InstallModes == nil {
		return "Unknown"
	}

	for _, mode := range csv.Spec.InstallModes {
		if mode.Supported {
			return string(mode.Type)
		}
	}

	return "Unknown"
}

func isTargetNamespace(ns string, targetNamespaces []string) bool {
	for _, target := range targetNamespaces {
		if ns == target {
			return true
		}
	}
	return false
}
