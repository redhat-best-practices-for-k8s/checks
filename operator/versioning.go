package operator

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var k8sVersionRegex = regexp.MustCompile(`^(v)([1-9]\d*)+((alpha|beta)([1-9]\d*)+){0,2}$`)

// CheckOperatorSemanticVersioning verifies that CSV versions are valid semantic versions.
func CheckOperatorSemanticVersioning(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.CSVs) == 0 {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Reason: "No CSVs found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		version := csv.Spec.Version.String()
		if isValidSemver(version) {
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: true, Message: fmt.Sprintf("Valid semantic version: %s", version),
			})
		} else {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "ClusterServiceVersion", Name: csv.Name, Namespace: csv.Namespace,
				Compliant: false, Message: fmt.Sprintf("Invalid semantic version: %s", version),
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Details: details}
	}
	return checks.CheckResult{ComplianceStatus: checks.StatusNonCompliant, Reason: "One or more CSVs have invalid semantic versioning", Details: details}
}

// isValidSemver checks if a version string is a valid semantic version.
// Accepts formats like "1.2.3", "v1.2.3", "1.2.3-rc1".
func isValidSemver(version string) bool {
	if version == "" {
		return false
	}
	v := strings.TrimPrefix(version, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 3 {
		return false
	}
	// Basic check: major.minor.patch where major/minor/patch start with digits
	for _, p := range parts[:3] {
		// Allow pre-release suffix on patch (e.g., "3-rc1")
		core := strings.SplitN(p, "-", 2)[0]
		if core == "" {
			return false
		}
		for _, c := range core {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// CheckCrdVersioning verifies that CRD versions follow Kubernetes versioning conventions
// (e.g., v1, v1alpha1, v1beta1).
func CheckCrdVersioning(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.CRDs) == 0 {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Reason: "No CRDs found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CRDs {
		crd := &resources.CRDs[i]
		valid := true
		invalidVersion := ""

		for _, ver := range crd.Spec.Versions {
			if !k8sVersionRegex.MatchString(ver.Name) {
				valid = false
				invalidVersion = ver.Name
				break
			}
		}

		if valid {
			details = append(details, checks.ResourceDetail{
				Kind: "CustomResourceDefinition", Name: crd.Name,
				Compliant: true, Message: "All versions follow K8s versioning",
			})
		} else {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "CustomResourceDefinition", Name: crd.Name,
				Compliant: false, Message: fmt.Sprintf("Invalid K8s version: %s", invalidVersion),
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Details: details}
	}
	return checks.CheckResult{ComplianceStatus: checks.StatusNonCompliant, Reason: "One or more CRDs have invalid K8s versioning", Details: details}
}

// CheckCrdOpenAPISchema verifies that CRDs have OpenAPI v3 schema defined.
func CheckCrdOpenAPISchema(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.CRDs) == 0 {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Reason: "No CRDs found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.CRDs {
		crd := &resources.CRDs[i]
		hasSchema := false
		for _, ver := range crd.Spec.Versions {
			if ver.Schema != nil && ver.Schema.OpenAPIV3Schema != nil {
				hasSchema = true
				break
			}
		}

		if hasSchema {
			details = append(details, checks.ResourceDetail{
				Kind: "CustomResourceDefinition", Name: crd.Name,
				Compliant: true, Message: "CRD has OpenAPI v3 schema",
			})
		} else {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "CustomResourceDefinition", Name: crd.Name,
				Compliant: false, Message: "CRD missing OpenAPI v3 schema",
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Details: details}
	}
	return checks.CheckResult{ComplianceStatus: checks.StatusNonCompliant, Reason: "One or more CRDs missing OpenAPI v3 schema", Details: details}
}
