package networking

import (
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckNetworkPolicyDenyAll verifies that each namespace with pods has a default-deny
// NetworkPolicy for both ingress and egress. A namespace is compliant if it has at least
// one network policy with an empty PodSelector that covers deny-all for ingress AND at
// least one that covers deny-all for egress. A single policy can cover both.
func CheckNetworkPolicyDenyAll(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	// Collect unique namespaces from pods.
	podNamespaces := make(map[string]bool)
	for i := range resources.Pods {
		podNamespaces[resources.Pods[i].Namespace] = true
	}

	// Pre-group deny-all policies by namespace in a single pass.
	type denyStatus struct{ ingress, egress bool }
	nsDeny := make(map[string]*denyStatus)
	for i := range resources.NetworkPolicies {
		np := &resources.NetworkPolicies[i]
		if !podNamespaces[np.Namespace] {
			continue
		}
		if len(np.Spec.PodSelector.MatchLabels) > 0 || len(np.Spec.PodSelector.MatchExpressions) > 0 {
			continue
		}
		ds, ok := nsDeny[np.Namespace]
		if !ok {
			ds = &denyStatus{}
			nsDeny[np.Namespace] = ds
		}
		for _, pt := range np.Spec.PolicyTypes {
			if pt == networkingv1.PolicyTypeIngress && len(np.Spec.Ingress) == 0 {
				ds.ingress = true
			}
			if pt == networkingv1.PolicyTypeEgress && len(np.Spec.Egress) == 0 {
				ds.egress = true
			}
		}
	}

	var count int
	for ns := range podNamespaces {
		ds := nsDeny[ns]
		hasDenyIngress := ds != nil && ds.ingress
		hasDenyEgress := ds != nil && ds.egress

		if !hasDenyIngress || !hasDenyEgress {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Namespace", Name: ns,
				Compliant: false,
				Message:   "Namespace is missing a default-deny NetworkPolicy for both ingress and egress",
			})
		}
	}

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d namespace(s) are missing default-deny NetworkPolicy for both ingress and egress", count)
	}
	return result
}
