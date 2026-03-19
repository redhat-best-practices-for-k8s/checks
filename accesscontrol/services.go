package accesscontrol

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckNodePortService verifies no services use NodePort type.
func CheckNodePortService(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Services) == 0 {
		return result
	}

	var count int
	for i := range resources.Services {
		svc := &resources.Services[i]
		if svc.Spec.Type == corev1.ServiceTypeNodePort {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Service", Name: svc.Name, Namespace: svc.Namespace,
				Compliant: false, Message: "Service type is NodePort",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d service(s) use NodePort type", count)
	}
	return result
}
