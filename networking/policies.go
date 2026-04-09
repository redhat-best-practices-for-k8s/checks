package networking

import (
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckNetworkPolicyDenyAll verifies that each pod under test is covered by deny-all
// network policies for both ingress and egress. Matching uses the certsuite's LabelsMatch
// logic: a policy matches a pod if its PodSelector is empty (matches all pods) OR if any
// of the PodSelector's MatchLabels are present in the pod's labels.
func CheckNetworkPolicyDenyAll(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		hasDenyIngress := false
		hasDenyEgress := false

		for j := range resources.NetworkPolicies {
			np := &resources.NetworkPolicies[j]
			if np.Namespace != pod.Namespace {
				continue
			}
			if !labelsMatch(np.Spec.PodSelector, pod.Labels) {
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
			if hasDenyIngress && hasDenyEgress {
				break
			}
		}

		if !hasDenyIngress || !hasDenyEgress {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod is not covered by deny-all NetworkPolicy for both ingress and egress",
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true,
				Message:   "Pod is covered by deny-all NetworkPolicy for both ingress and egress",
			})
		}
	}

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) are not covered by deny-all NetworkPolicy for both ingress and egress", count)
	}
	return result
}

// labelsMatch returns true if the pod selector matches the pod's labels.
// An empty selector (no MatchLabels and no MatchExpressions) matches all pods.
// Otherwise, each MatchLabel key must exist in the pod's labels with the same value.
func labelsMatch(selector metav1.LabelSelector, podLabels map[string]string) bool {
	if len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
		return true
	}
	for key, val := range selector.MatchLabels {
		if podLabels[key] != val {
			return false
		}
	}
	return true
}
