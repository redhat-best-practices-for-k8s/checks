package accesscontrol

import (
	"fmt"
	"strings"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// invalidNamespacePrefixes are prefixes that identify system namespaces where workloads should not run.
// This matches the certsuite's namespace validation logic.
var invalidNamespacePrefixes = []string{
	"default",
	"openshift-",
	"istio-",
	"aspenmesh-",
}

// isInvalidNamespace returns true if the namespace starts with any of the invalid prefixes.
func isInvalidNamespace(namespace string) bool {
	for _, prefix := range invalidNamespacePrefixes {
		if strings.HasPrefix(namespace, prefix) {
			return true
		}
	}
	return false
}

// CheckNamespace verifies pods run in allowed namespaces.
func CheckNamespace(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int

	// Check pod namespaces for invalid prefixes
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if isInvalidNamespace(pod.Namespace) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Pod is running in system namespace %q", pod.Namespace),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true,
				Message:   fmt.Sprintf("Pod is running in allowed namespace %q", pod.Namespace),
			})
		}
	}

	// Check that CRs exist only in configured namespaces
	if len(resources.CRInstances) > 0 && len(resources.Namespaces) > 0 {
		nsSet := make(map[string]bool, len(resources.Namespaces))
		for _, ns := range resources.Namespaces {
			nsSet[ns] = true
		}
		for crdName, nsCRs := range resources.CRInstances {
			for ns, crNames := range nsCRs {
				if !nsSet[ns] {
					for _, crName := range crNames {
						count++
						result.Details = append(result.Details, checks.ResourceDetail{
							Kind: "CustomResource", Name: crName, Namespace: ns,
							Compliant: false,
							Message:   fmt.Sprintf("CR from CRD %q exists in namespace %q which is not a configured namespace", crdName, ns),
						})
					}
				}
			}
		}
	}

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d namespace violation(s) found", count)
	}
	return result
}

// CheckNamespaceResourceQuota verifies each pod runs in a namespace that has a ResourceQuota.
// For each pod under test, it checks whether any ResourceQuota exists in that pod's namespace.
func CheckNamespaceResourceQuota(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	// Build a set of namespaces that have at least one ResourceQuota.
	quotaNamespaces := make(map[string]bool, len(resources.ResourceQuotas))
	for i := range resources.ResourceQuotas {
		quotaNamespaces[resources.ResourceQuotas[i].Namespace] = true
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if !quotaNamespaces[pod.Namespace] {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod is running in a namespace that does not have a ResourceQuota applied",
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true,
				Message:   "Pod is running in a namespace with a ResourceQuota applied",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) are running in namespaces without a ResourceQuota", count)
	}
	return result
}
