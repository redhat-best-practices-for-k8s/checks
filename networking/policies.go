package networking

import (
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckNetworkPolicyDenyAll verifies a default-deny NetworkPolicy exists.
func CheckNetworkPolicyDenyAll(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	hasDenyIngress := false
	hasDenyEgress := false

	for i := range resources.NetworkPolicies {
		np := &resources.NetworkPolicies[i]

		if len(np.Spec.PodSelector.MatchLabels) > 0 || len(np.Spec.PodSelector.MatchExpressions) > 0 {
			continue
		}

		for _, pt := range np.Spec.PolicyTypes {
			if pt == networkingv1.PolicyTypeIngress && len(np.Spec.Ingress) == 0 {
				hasDenyIngress = true
			}
			if pt == networkingv1.PolicyTypeEgress && len(np.Spec.Egress) == 0 {
				hasDenyEgress = true
			}
		}
	}

	if !hasDenyIngress || !hasDenyEgress {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = "No default-deny NetworkPolicy found for both ingress and egress"
		if len(resources.Namespaces) > 0 {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Namespace", Name: resources.Namespaces[0],
				Compliant: false,
				Message:   "Namespace is missing a default-deny NetworkPolicy",
			})
		}
	}
	return result
}
