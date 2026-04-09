package accesscontrol

import (
	"fmt"
	"strings"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckCrdRoles verifies that Roles in target namespaces only grant permissions on CRD resources.
// Logic (matching certsuite):
//  1. Only checks roles in target namespaces
//  2. Builds a set of CRD group+plural name pairs
//  3. Only evaluates roles that have at least one rule matching a CRD resource
//  4. For matching roles, flags rules that reference non-CRD resources
func CheckCrdRoles(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Roles) == 0 || len(resources.CRDs) == 0 {
		result.Reason = "No roles or CRDs found"
		return result
	}

	// Build a map of CRD resources for O(1) lookup: "group/plural" -> true
	crdSet := make(map[string]bool, len(resources.CRDs))
	for i := range resources.CRDs {
		crd := &resources.CRDs[i]
		crdSet[crd.Spec.Group+"/"+crd.Spec.Names.Plural] = true
	}

	namespaceSet := make(map[string]bool, len(resources.Namespaces))
	for _, ns := range resources.Namespaces {
		namespaceSet[ns] = true
	}

	var nonCompliantCount int
	for i := range resources.Roles {
		role := &resources.Roles[i]

		if !namespaceSet[role.Namespace] {
			continue
		}

		// Check if this role touches any CRD resource (by group + plural name).
		// We match at (group, resource) granularity -- verbs are irrelevant for the decision.
		hasCRDRule := false
		hasNonCRDRule := false
		for _, pr := range role.Rules {
			for _, group := range pr.APIGroups {
				for _, resource := range pr.Resources {
					resourceName := strings.Split(resource, "/")[0] // strip subresource
					if crdSet[group+"/"+resourceName] {
						hasCRDRule = true
					} else {
						hasNonCRDRule = true
					}
				}
			}
		}

		// Skip roles that don't touch any CRD resource
		if !hasCRDRule {
			continue
		}

		if hasNonCRDRule {
			nonCompliantCount++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Role", Name: role.Name, Namespace: role.Namespace,
				Compliant: false,
				Message:   "Role grants access to both CRD resources and non-CRD resources",
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Role", Name: role.Name, Namespace: role.Namespace,
				Compliant: true,
				Message:   "Role only grants access to CRD resources",
			})
		}
	}

	if nonCompliantCount > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d role(s) grant access beyond CRD resources", nonCompliantCount)
	}
	return result
}
