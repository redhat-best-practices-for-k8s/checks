package observability

import (
	"fmt"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckCRDStatus verifies CRDs have a .status subresource defined.
func CheckCRDStatus(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.CRDs) == 0 {
		return result
	}

	var count int
	for i := range resources.CRDs {
		crd := &resources.CRDs[i]
		if !crdHasStatusSubresource(crd) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "CustomResourceDefinition", Name: crd.Name, Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("CRD %q does not define a .status subresource", crd.Name),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d CRD(s) missing .status subresource", count)
	}
	return result
}

func crdHasStatusSubresource(crd *apiextv1.CustomResourceDefinition) bool {
	for _, version := range crd.Spec.Versions {
		if version.Subresources != nil && version.Subresources.Status != nil {
			return true
		}
		if version.Schema != nil && version.Schema.OpenAPIV3Schema != nil {
			if _, ok := version.Schema.OpenAPIV3Schema.Properties["status"]; ok {
				return true
			}
		}
	}
	return false
}
