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
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
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
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d port name(s) do not follow IANA format", count)
	}
	return result
}

// CheckImageTag verifies container images use a digest or specific tag, not :latest.
func CheckImageTag(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachPodContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if isLatestOrUntagged(container.Image) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q uses image %q (latest or untagged)", container.Name, container.Image),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d container(s) use :latest or untagged images", count)
	}
	return result
}

func isLatestOrUntagged(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	if strings.HasSuffix(image, ":latest") {
		return true
	}
	parts := strings.Split(image, "/")
	lastPart := parts[len(parts)-1]
	return !strings.Contains(lastPart, ":")
}
