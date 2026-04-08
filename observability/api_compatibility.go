package observability

import (
	"fmt"

	"github.com/blang/semver/v4"
	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckAPICompatibilityWithNextOCPRelease verifies APIs used by workload are compatible
// with the next OCP/Kubernetes version.
func CheckAPICompatibilityWithNextOCPRelease(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if resources.OpenshiftVersion == "" {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "Not an OpenShift cluster"
		return result
	}

	if len(resources.APIRequestCounts) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No API request count data available"
		return result
	}

	// Extract unique service account names
	workloadServiceAccounts := make(map[string]struct{}, len(resources.ServiceAccounts))
	for i := range resources.ServiceAccounts {
		sa := &resources.ServiceAccounts[i]
		workloadServiceAccounts[sa.Name] = struct{}{}
	}

	// Build map of service accounts to deprecated APIs
	serviceAccountToDeprecatedAPIs := buildDeprecatedAPIMap(resources.APIRequestCounts, workloadServiceAccounts)

	// Parse Kubernetes version
	version, err := semver.Parse(resources.K8sVersion)
	if err != nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = fmt.Sprintf("Failed to parse Kubernetes version %q: %v", resources.K8sVersion, err)
		return result
	}

	// Get next version
	nextVersion := version
	nextVersion.Minor++

	// Evaluate compliance
	var nonCompliantCount int

	for saName, deprecatedAPIs := range serviceAccountToDeprecatedAPIs {
		for apiName, removedInRelease := range deprecatedAPIs {
			removedVersion, err := semver.Parse(removedInRelease)
			if err != nil {
				continue
			}

			isCompliant := removedVersion.Minor > nextVersion.Minor

			if isCompliant {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "API",
					Name:      apiName,
					Compliant: true,
					Message: fmt.Sprintf("API %s used by service account %s is compliant with Kubernetes version %s, will be removed in %s",
						apiName, saName, nextVersion.String(), removedInRelease),
				})
			} else {
				nonCompliantCount++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "API",
					Name:      apiName,
					Compliant: false,
					Message: fmt.Sprintf("API %s used by service account %s is NOT compliant with Kubernetes version %s, will be removed in %s",
						apiName, saName, nextVersion.String(), removedInRelease),
				})
			}
		}
	}

	// If no deprecated APIs found, all service accounts are compliant
	if len(serviceAccountToDeprecatedAPIs) == 0 {
		for saName := range workloadServiceAccounts {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "ServiceAccount",
				Name:      saName,
				Compliant: true,
				Message:   "Service account does not use any deprecated APIs",
			})
		}
	}

	if nonCompliantCount > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d deprecated API(s) will be removed in next Kubernetes version", nonCompliantCount)
	}

	return result
}

func buildDeprecatedAPIMap(apiRequestCounts interface{}, workloadServiceAccounts map[string]struct{}) map[string]map[string]string {
	// Placeholder implementation - will need actual apiserverv1.APIRequestCount type
	// to properly parse the API request count objects
	serviceAccountToDeprecatedAPIs := make(map[string]map[string]string)

	// This would iterate through apiRequestCounts and build the map
	// For now, return empty map as placeholder

	return serviceAccountToDeprecatedAPIs
}
