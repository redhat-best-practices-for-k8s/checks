package operator

import (
	"fmt"
	"strings"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
)

// CheckSingleCrdOwner verifies that each CRD is owned by exactly one operator CSV.
func CheckSingleCrdOwner(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.CSVs) == 0 {
		return checks.CheckResult{ComplianceStatus: checks.StatusSkipped, Reason: "No CSVs found"}
	}

	// Map each CRD name to operators that own it
	crdOwners := map[string][]string{}
	for i := range resources.CSVs {
		csv := &resources.CSVs[i]
		uniqueOwned := map[string]struct{}{}
		for _, owned := range csv.Spec.CustomResourceDefinitions.Owned {
			uniqueOwned[owned.Name] = struct{}{}
		}
		for crdName := range uniqueOwned {
			crdOwners[crdName] = append(crdOwners[crdName], csv.Name)
		}
	}

	if len(crdOwners) == 0 {
		return checks.CheckResult{ComplianceStatus: checks.StatusSkipped, Reason: "No owned CRDs found in CSVs"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for crd, owners := range crdOwners {
		if len(owners) > 1 {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "CustomResourceDefinition", Name: crd,
				Compliant: false, Message: fmt.Sprintf("Owned by multiple operators: %s", strings.Join(owners, ", ")),
			})
		} else {
			details = append(details, checks.ResourceDetail{
				Kind: "CustomResourceDefinition", Name: crd,
				Compliant: true, Message: fmt.Sprintf("Owned by single operator: %s", owners[0]),
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Details: details}
	}
	return checks.CheckResult{ComplianceStatus: checks.StatusNonCompliant, Reason: "One or more CRDs owned by multiple operators", Details: details}
}

// CheckOperatorPodsNoHugepages verifies that pods associated with operators
// do not request hugepages resources.
func CheckOperatorPodsNoHugepages(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.Pods) == 0 {
		return checks.CheckResult{ComplianceStatus: checks.StatusSkipped, Reason: "No pods found"}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if podHasHugepages(pod) {
			allCompliant = false
			details = append(details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false, Message: "Pod has hugepages enabled",
			})
		} else {
			details = append(details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true, Message: "Pod has no hugepages",
			})
		}
	}

	if allCompliant {
		return checks.CheckResult{ComplianceStatus: checks.StatusCompliant, Details: details}
	}
	return checks.CheckResult{ComplianceStatus: checks.StatusNonCompliant, Reason: "One or more pods have hugepages", Details: details}
}

func podHasHugepages(pod *corev1.Pod) bool {
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		for resName := range c.Resources.Requests {
			if strings.HasPrefix(string(resName), "hugepages-") {
				return true
			}
		}
		for resName := range c.Resources.Limits {
			if strings.HasPrefix(string(resName), "hugepages-") {
				return true
			}
		}
	}
	return false
}
