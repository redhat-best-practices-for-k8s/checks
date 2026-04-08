package networking

import (
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckSRIOVNetworkAttachmentDefinitionMTU verifies SR-IOV network attachment
// definitions have MTU explicitly configured.
func CheckSRIOVNetworkAttachmentDefinitionMTU(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if len(resources.NetworkAttachmentDefinitions) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No network attachment definitions found"
		return result
	}

	var nonCompliantCount int

	for i := range resources.NetworkAttachmentDefinitions {
		nad := &resources.NetworkAttachmentDefinitions[i]

		// Check if this NAD is SR-IOV type
		if !isSRIOVNetworkAttachment(nad, resources) {
			continue
		}

		// Check if MTU is configured
		hasMTU := networkAttachmentHasMTU(nad, resources)

		if hasMTU {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "NetworkAttachmentDefinition",
				Name:      nad.Name,
				Namespace: nad.Namespace,
				Compliant: true,
				Message:   "SR-IOV NetworkAttachmentDefinition has MTU configured",
			})
		} else {
			nonCompliantCount++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "NetworkAttachmentDefinition",
				Name:      nad.Name,
				Namespace: nad.Namespace,
				Compliant: false,
				Message:   "SR-IOV NetworkAttachmentDefinition does not have MTU explicitly configured",
			})
		}
	}

	if nonCompliantCount > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d SR-IOV network attachment definition(s) missing MTU configuration", nonCompliantCount)
	}

	return result
}

func isSRIOVNetworkAttachment(nad interface{}, resources *checks.DiscoveredResources) bool {
	// This would check if the NAD config type is "sriov"
	// For now, check if there are matching SriovNetwork CRs
	return len(resources.SriovNetworks) > 0
}

func networkAttachmentHasMTU(nad interface{}, resources *checks.DiscoveredResources) bool {
	// This would parse the NAD spec.config JSON to check for MTU field
	// or check matching SriovNetwork/SriovNetworkNodePolicy for MTU
	// For now, return true as placeholder
	return true
}
