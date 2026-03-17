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
	// Check each pod for default SA usage and cross-namespace role bindings
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

		// Find cross-namespace role bindings for this service account
		violations := findCrossNamespaceRoleBindings(pod, resources.RoleBindings, targetNS)
		count += len(violations)
		result.Details = append(result.Details, violations...)
	}

	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d role binding issue(s) found", count)
	}
	return result
}

// findCrossNamespaceRoleBindings finds role bindings that reference the pod's service account
// from a namespace different than the pod's namespace and not in the target namespace set.
func findCrossNamespaceRoleBindings(pod *corev1.Pod, roleBindings []rbacv1.RoleBinding, targetNS map[string]bool) []checks.ResourceDetail {
	var violations []checks.ResourceDetail

	for j := range roleBindings {
		rb := &roleBindings[j]

		// Skip role bindings in the same namespace as the pod
		if rb.Namespace == pod.Namespace {
			continue
		}

		// Check if this role binding references the pod's service account
		if roleBindingReferencesServiceAccount(rb, pod.Namespace, pod.Spec.ServiceAccountName) {
			// Violation: role binding is in a non-target namespace
			if !targetNS[rb.Namespace] {
				violations = append(violations, checks.ResourceDetail{
					Kind:      "RoleBinding",
					Name:      rb.Name,
					Namespace: rb.Namespace,
					Compliant: false,
					Message: fmt.Sprintf("RoleBinding in non-target namespace %q references ServiceAccount %s/%s",
						rb.Namespace, pod.Namespace, pod.Spec.ServiceAccountName),
				})
			}
		}
	}

	return violations
}

// roleBindingReferencesServiceAccount checks if a RoleBinding has a subject that matches
// the given service account namespace and name.
func roleBindingReferencesServiceAccount(rb *rbacv1.RoleBinding, namespace, name string) bool {
	for _, subject := range rb.Subjects {
		if subject.Kind == rbacv1.ServiceAccountKind &&
			subject.Namespace == namespace &&
			subject.Name == name {
			return true
		}
	}
	return false
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
