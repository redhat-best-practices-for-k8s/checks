package accesscontrol

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckServiceAccount verifies pods do not use the default service account.
func CheckServiceAccount(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default" {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false, Message: "Pod uses the default service account",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d pod(s) use the default service account", count)
	}
	return result
}

// CheckRoleBindings verifies that role bindings used by pod service accounts
// live within the target namespaces.
func CheckRoleBindings(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		return result
	}

	targetNS := make(map[string]bool, len(resources.Namespaces))
	for _, ns := range resources.Namespaces {
		targetNS[ns] = true
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]

		if pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default" {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod uses empty or default serviceAccountName",
			})
			continue
		}

		for j := range resources.RoleBindings {
			rb := &resources.RoleBindings[j]
			if rb.Namespace == pod.Namespace {
				continue
			}
			for _, subject := range rb.Subjects {
				if subject.Kind != rbacv1.ServiceAccountKind {
					continue
				}
				if subject.Namespace == pod.Namespace && subject.Name == pod.Spec.ServiceAccountName {
					if !targetNS[rb.Namespace] {
						count++
						result.Details = append(result.Details, checks.ResourceDetail{
							Kind: "RoleBinding", Name: rb.Name, Namespace: rb.Namespace,
							Compliant: false,
							Message: fmt.Sprintf("RoleBinding in non-target namespace %q references ServiceAccount %s/%s",
								rb.Namespace, pod.Namespace, pod.Spec.ServiceAccountName),
						})
					}
				}
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d role binding issue(s) found", count)
	}
	return result
}

// CheckClusterRoleBindings verifies pods are not linked to ClusterRoleBindings.
func CheckClusterRoleBindings(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.ClusterRoleBindings) == 0 || len(resources.Pods) == 0 {
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}

		for j := range resources.ClusterRoleBindings {
			crb := &resources.ClusterRoleBindings[j]
			for _, subject := range crb.Subjects {
				if subject.Kind == rbacv1.ServiceAccountKind &&
					subject.Name == sa &&
					subject.Namespace == pod.Namespace {
					count++
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind: "ClusterRoleBinding", Name: crb.Name, Namespace: "",
						Compliant: false,
						Message: fmt.Sprintf("Binds ServiceAccount %s/%s (ClusterRole: %s)",
							pod.Namespace, sa, crb.RoleRef.Name),
					})
				}
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d ClusterRoleBinding(s) bind pod ServiceAccounts", count)
	}
	return result
}

// CheckAutomountToken verifies pods do not automount service account tokens.
func CheckAutomountToken(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	saAutomount := make(map[string]*bool)
	for i := range resources.ServiceAccounts {
		sa := &resources.ServiceAccounts[i]
		saAutomount[sa.Namespace+"/"+sa.Name] = sa.AutomountServiceAccountToken
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]

		if pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default" {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false, Message: "Pod uses the default service account",
			})
			continue
		}

		if automountEnabled(pod, saAutomount) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false, Message: "Service account token is automounted",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d pod(s) have automount token issues", count)
	}
	return result
}

func automountEnabled(pod *corev1.Pod, saAutomount map[string]*bool) bool {
	if pod.Spec.AutomountServiceAccountToken != nil {
		return *pod.Spec.AutomountServiceAccountToken
	}
	saKey := pod.Namespace + "/" + pod.Spec.ServiceAccountName
	if saVal, ok := saAutomount[saKey]; ok && saVal != nil {
		return *saVal
	}
	return true
}
