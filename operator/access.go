package operator

import (
	"github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckOperatorNoSCCAccess verifies that operator CSVs do not grant access to
// Security Context Constraints via their clusterPermissions.
func CheckOperatorNoSCCAccess(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.CSVs) == 0 {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Reason: "No CSVs found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		clusterPermissions := csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions
		if len(clusterPermissions) == 0 {
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: true, Message: "No clusterPermissions found",
			})
			continue
		}

		if permissionsHaveSCCAccess(clusterPermissions) {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: false, Message: "RBAC rules grant access to SecurityContextConstraints",
			})
		} else {
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: true, Message: "No RBAC rules for SecurityContextConstraints",
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Details: details}
	}
	return checks.CheckResult{ComplianceStatus: checks.StatusNonCompliant, Reason: "One or more CSVs grant SCC access", Details: details}
}

func permissionsHaveSCCAccess(clusterPermissions []v1alpha1.StrategyDeploymentPermissions) bool {
	for i := range clusterPermissions {
		for j := range clusterPermissions[i].Rules {
			rule := &clusterPermissions[i].Rules[j]
			securityGroupFound := false
			for _, group := range rule.APIGroups {
				if group == "*" || group == "security.openshift.io" {
					securityGroupFound = true
					break
				}
			}
			if !securityGroupFound {
				continue
			}
			for _, resource := range rule.Resources {
				if resource == "*" || resource == "securitycontextconstraints" {
					return true
				}
			}
		}
	}
	return false
}
