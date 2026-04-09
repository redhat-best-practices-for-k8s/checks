package manageability

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// allowedProtocolNames defines the valid protocol prefixes for container port names.
// The port name format is <protocol>[-<suffix>] where protocol must be one of these.
var allowedProtocolNames = map[string]bool{
	"grpc":  true,
	"http":  true,
	"http2": true,
	"tcp":   true,
	"udp":   true,
}

// portNameFormatCheck validates a container port name follows the format
// <protocol>[-<suffix>] where <protocol> is one of the allowed protocol names.
func portNameFormatCheck(portName string) bool {
	res := strings.Split(portName, "-")
	return allowedProtocolNames[res[0]]
}

// CheckPortNameFormat verifies container port names follow the naming convention
// <protocol>[-<suffix>] where protocol is one of: grpc, http, http2, tcp, udp.
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
			if !portNameFormatCheck(port.Name) {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q port name %q does not follow the naming convention <protocol>[-<suffix>]", container.Name, port.Name),
				})
			}
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d port name(s) do not follow the naming convention", count)
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
