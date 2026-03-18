package certification

import (
	"fmt"
	"strings"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckOperatorCertified verifies that all operators (CSVs) are Red Hat certified
// for the current OpenShift version.
func CheckOperatorCertified(resources *checks.DiscoveredResources) checks.CheckResult {
	if resources.CertValidator == nil {
		return checks.CheckResult{
			ComplianceStatus: "Skipped",
			Reason:           "No certification validator available",
		}
	}

	if len(resources.CSVs) == 0 {
		return checks.CheckResult{
			ComplianceStatus: "Skipped",
			Reason:           "No operators to check",
		}
	}

	ocpMinorVersion := extractOCPMinorVersion(resources.OpenshiftVersion)

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		if resources.CertValidator.IsOperatorCertified(csv.Name, ocpMinorVersion) {
			details = append(details, checks.ResourceDetail{
				Kind:      "ClusterServiceVersion",
				Name:      csv.Name,
				Namespace: csv.Namespace,
				Compliant: true,
				Message:   fmt.Sprintf("Operator is certified for OpenShift %s", ocpMinorVersion),
			})
		} else {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind:      "ClusterServiceVersion",
				Name:      csv.Name,
				Namespace: csv.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Operator is not certified for OpenShift %s", ocpMinorVersion),
			})
		}
	}

	status := "Compliant"
	reason := "All operators are certified"
	if !allCompliant {
		status = "NonCompliant"
		reason = "One or more operators are not certified"
	}

	return checks.CheckResult{
		ComplianceStatus: status,
		Reason:           reason,
		Details:          details,
	}
}

// extractOCPMinorVersion converts "4.13.5" to "4.13".
// Returns empty string if the version is empty or not an OCP cluster.
func extractOCPMinorVersion(version string) string {
	if version == "" {
		return ""
	}
	const majorMinorPatchCount = 3
	parts := strings.SplitN(version, ".", majorMinorPatchCount)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}
