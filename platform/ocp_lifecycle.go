package platform

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// Lifecycle status constants
const (
	OCPStatusGA    = "GA"
	OCPStatusMS    = "MS"
	OCPStatusEOL   = "EOL"
	OCPStatusPreGA = "PreGA"
)

// CheckOCPLifecycle verifies the OCP version is not end-of-life.
func CheckOCPLifecycle(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}

	if resources.OpenshiftVersion == "" {
		result.ComplianceStatus = "Skipped"
		result.Reason = "Not an OpenShift cluster"
		return result
	}

	if resources.OCPStatus == OCPStatusEOL {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("OCP version %s is end-of-life", resources.OpenshiftVersion)
		result.Details = append(result.Details, checks.ResourceDetail{
			Kind:      "ClusterVersion",
			Name:      resources.OpenshiftVersion,
			Compliant: false,
			Message:   "OpenShift version is in End Of Life (EOL)",
		})
	} else {
		var status string
		switch resources.OCPStatus {
		case OCPStatusGA:
			status = "general availability"
		case OCPStatusMS:
			status = "maintenance support"
		case OCPStatusPreGA:
			status = "pre-general availability"
		default:
			status = "unknown lifecycle status"
		}
		result.Reason = fmt.Sprintf("OCP version %s is in %s", resources.OpenshiftVersion, status)
	}

	return result
}

// CheckOCPNodeOSLifecycle verifies node operating systems are compatible with OCP version.
func CheckOCPNodeOSLifecycle(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}

	if resources.OpenshiftVersion == "" {
		result.ComplianceStatus = "Skipped"
		result.Reason = "Not an OpenShift cluster"
		return result
	}

	if len(resources.Nodes) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No nodes found"
		return result
	}

	var failedNodes []string

	for i := range resources.Nodes {
		node := &resources.Nodes[i]
		nodeName := node.Name
		osImage := node.Status.NodeInfo.OSImage

		// Control plane nodes must be RHCOS or CentOS Stream CoreOS
		isControlPlane := false
		if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
			isControlPlane = true
		}
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			isControlPlane = true
		}

		if isControlPlane {
			// Check if it's RHCOS or CentOS Stream CoreOS
			if !isRHCOS(osImage) && !isCSCOS(osImage) {
				failedNodes = append(failedNodes, nodeName)
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Node",
					Name:      nodeName,
					Compliant: false,
					Message:   fmt.Sprintf("Control plane node has incompatible OS: %s", osImage),
				})
			}
		}
	}

	if len(failedNodes) > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d node(s) have incompatible operating system", len(failedNodes))
	}

	return result
}

func isRHCOS(osImage string) bool {
	return contains(osImage, "Red Hat Enterprise Linux CoreOS") ||
		contains(osImage, "RHCOS")
}

func isCSCOS(osImage string) bool {
	return contains(osImage, "CentOS Stream CoreOS")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
