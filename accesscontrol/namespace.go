package accesscontrol

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// defaultNamespaces are Kubernetes/OpenShift system namespaces where workloads should not run.
var defaultNamespaces = map[string]bool{
	"default":                              true,
	"kube-system":                          true,
	"kube-public":                          true,
	"kube-node-lease":                      true,
	"openshift":                            true,
	"openshift-apiserver":                  true,
	"openshift-authentication":             true,
	"openshift-config":                     true,
	"openshift-console":                    true,
	"openshift-controller-manager":         true,
	"openshift-dns":                        true,
	"openshift-etcd":                       true,
	"openshift-image-registry":             true,
	"openshift-infra":                      true,
	"openshift-ingress":                    true,
	"openshift-kube-apiserver":             true,
	"openshift-kube-controller-manager":    true,
	"openshift-kube-scheduler":             true,
	"openshift-machine-api":                true,
	"openshift-machine-config-operator":    true,
	"openshift-marketplace":                true,
	"openshift-monitoring":                 true,
	"openshift-multus":                     true,
	"openshift-network-operator":           true,
	"openshift-node":                       true,
	"openshift-operator-lifecycle-manager": true,
	"openshift-operators":                  true,
	"openshift-sdn":                        true,
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
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if defaultNamespaces[pod.Namespace] {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Pod is running in system namespace %q", pod.Namespace),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) are running in system namespaces", count)
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
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) are running in namespaces without a ResourceQuota", count)
	}
	return result
}
