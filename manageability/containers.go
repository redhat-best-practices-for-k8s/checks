package manageability

import (
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var ianaPortNameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$`)

// CheckPortNameFormat verifies container port names follow IANA naming conventions.
func CheckPortNameFormat(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		for _, port := range container.Ports {
			if port.Name == "" {
				continue
			}
			if !ianaPortNameRegex.MatchString(port.Name) {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q port name %q does not follow IANA format", container.Name, port.Name),
				})
			}
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d port name(s) do not follow IANA format", count)
	}
	return result
}

// CheckImageTag verifies container images have a tag or digest.
// The certsuite logic: an image is non-compliant only if it has no tag at all
// (and no digest). The ":latest" tag is a valid tag and is compliant.
func CheckImageTag(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachPodContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if isUntagged(container.Image) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q uses image %q with no tag", container.Name, container.Image),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) use untagged images", count)
	}
	return result
}

// isUntagged returns true if the image has no tag and no digest.
// An image with ":latest" is tagged and returns false (compliant).
func isUntagged(image string) bool {
	// Has a digest reference - always considered tagged
	if strings.Contains(image, "@sha256:") {
		return false
	}
	// Check whether the image name portion (after the last /) contains a colon (tag separator)
	parts := strings.Split(image, "/")
	lastPart := parts[len(parts)-1]
	return !strings.Contains(lastPart, ":")
}
