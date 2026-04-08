package observability

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckPodDisruptionBudget verifies PodDisruptionBudgets exist for HA workloads.
func CheckPodDisruptionBudget(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Deployments) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No deployments found"
		return result
	}

	pdbSelectors := make(map[string]bool)
	for i := range resources.PodDisruptionBudgets {
		pdb := &resources.PodDisruptionBudgets[i]
		for k, v := range pdb.Spec.Selector.MatchLabels {
			pdbSelectors[k+"="+v] = true
		}
	}

	var count int
	for i := range resources.Deployments {
		deploy := &resources.Deployments[i]
		replicas := int32(1)
		if deploy.Spec.Replicas != nil {
			replicas = *deploy.Spec.Replicas
		}
		if replicas < 2 {
			continue
		}

		matched := false
		for k, v := range deploy.Spec.Template.Labels {
			if pdbSelectors[k+"="+v] {
				matched = true
				break
			}
		}
		if !matched {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Deployment", Name: deploy.Name, Namespace: deploy.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("HA Deployment (%d replicas) has no PodDisruptionBudget", replicas),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d HA deployment(s) missing PodDisruptionBudget", count)
	}
	return result
}
