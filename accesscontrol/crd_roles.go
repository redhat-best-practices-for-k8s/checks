package accesscontrol

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckCrdRoles verifies that Roles only grant permissions on CRDs under test.
func CheckCrdRoles(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Roles) == 0 || len(resources.CRDs) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No roles or CRDs found"
		return result
	}

	crdResources := make(map[string]bool)
	for i := range resources.CRDs {
		crd := &resources.CRDs[i]
		crdResources[crd.Spec.Names.Plural] = true
		if crd.Spec.Names.Singular != "" {
			crdResources[crd.Spec.Names.Singular] = true
		}
		for _, shortName := range crd.Spec.Names.ShortNames {
			crdResources[shortName] = true
		}
	}

	var count int
	for i := range resources.Roles {
		role := &resources.Roles[i]
		for _, rule := range role.Rules {
			for _, res := range rule.Resources {
				if res == "*" {
					count++
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind: "Role", Name: role.Name, Namespace: role.Namespace,
						Compliant: false,
						Message:   "Role grants wildcard (*) resource access",
					})
					break
				}
				if !crdResources[res] {
					count++
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind: "Role", Name: role.Name, Namespace: role.Namespace,
						Compliant: false,
						Message:   fmt.Sprintf("Role grants access to non-CRD resource %q", res),
					})
				}
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d role rule(s) grant access beyond CRD resources", count)
	}
	return result
}
