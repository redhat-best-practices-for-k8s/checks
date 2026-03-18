package certification

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckHelmChartCertified verifies that all Helm chart releases are Red Hat certified.
func CheckHelmChartCertified(resources *checks.DiscoveredResources) checks.CheckResult {
	if resources.CertValidator == nil {
		return checks.CheckResult{
			ComplianceStatus: "Skipped",
			Reason:           "No certification validator available",
		}
	}

	if len(resources.HelmChartReleases) == 0 {
		return checks.CheckResult{
			ComplianceStatus: "Skipped",
			Reason:           "No Helm chart releases to check",
		}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for _, helm := range resources.HelmChartReleases {
		if resources.CertValidator.IsHelmChartCertified(helm.Name, helm.Version, resources.K8sVersion) {
			details = append(details, checks.ResourceDetail{
				Kind:      "HelmRelease",
				Name:      helm.Name,
				Namespace: helm.Namespace,
				Compliant: true,
				Message:   fmt.Sprintf("Helm chart version %s is certified", helm.Version),
			})
		} else {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind:      "HelmRelease",
				Name:      helm.Name,
				Namespace: helm.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Helm chart version %s is not certified", helm.Version),
			})
		}
	}

	status := "Compliant"
	reason := "All Helm charts are certified"
	if !allCompliant {
		status = "NonCompliant"
		reason = "One or more Helm charts are not certified"
	}

	return checks.CheckResult{
		ComplianceStatus: status,
		Reason:           reason,
		Details:          details,
	}
}
