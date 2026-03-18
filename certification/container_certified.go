package certification

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckContainerCertified verifies that all container images are Red Hat certified
// by checking their digest against the certification database.
func CheckContainerCertified(resources *checks.DiscoveredResources) checks.CheckResult {
	if resources.CertValidator == nil {
		return checks.CheckResult{
			ComplianceStatus: "Skipped",
			Reason:           "No certification validator available",
		}
	}

	if len(resources.Pods) == 0 {
		return checks.CheckResult{
			ComplianceStatus: "Skipped",
			Reason:           "No pods to check",
		}
	}

	var details []checks.ResourceDetail
	allCompliant := true

	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]

			// Find the matching container status for the imageID (digest)
			imageID := ""
			for k := range pod.Status.ContainerStatuses {
				if pod.Status.ContainerStatuses[k].Name == container.Name {
					imageID = pod.Status.ContainerStatuses[k].ImageID
					break
				}
			}

			registry, repository, tag, digest := parseContainerImage(container.Image, imageID)

			detailName := fmt.Sprintf("%s/%s", pod.Name, container.Name)

			if digest == "" {
				allCompliant = false
				details = append(details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      detailName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Missing digest field (registry=%s, repository=%s)", registry, repository),
				})
				continue
			}

			if !resources.CertValidator.IsContainerCertified(registry, repository, tag, digest) {
				allCompliant = false
				details = append(details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      detailName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Digest not found in certification database (registry=%s, repository=%s, tag=%s, digest=%s)", registry, repository, tag, digest),
				})
			} else {
				details = append(details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      detailName,
					Namespace: pod.Namespace,
					Compliant: true,
					Message:   "Container image is certified",
				})
			}
		}
	}

	if len(details) == 0 {
		return checks.CheckResult{
			ComplianceStatus: "Skipped",
			Reason:           "No containers to check",
		}
	}

	status := "Compliant"
	reason := "All container images are certified"
	if !allCompliant {
		status = "NonCompliant"
		reason = "One or more container images are not certified"
	}

	return checks.CheckResult{
		ComplianceStatus: status,
		Reason:           reason,
		Details:          details,
	}
}
