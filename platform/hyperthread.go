package platform

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
)

// CheckHyperthreadEnable verifies bare metal nodes have hyperthreading enabled.
func CheckHyperthreadEnable(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: "Compliant"}

	if resources.ProbeExecutor == nil {
		result.ComplianceStatus = "Error"
		result.Reason = "ProbeExecutor not available for hyperthread checks"
		return result
	}

	if len(resources.Nodes) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No nodes found"
		return result
	}

	// Filter for bare metal nodes (nodes without cloud provider labels)
	var bareMetalNodes []corev1.Node
	for i := range resources.Nodes {
		node := &resources.Nodes[i]
		if isBareMetalNode(node) {
			bareMetalNodes = append(bareMetalNodes, *node)
		}
	}

	if len(bareMetalNodes) == 0 {
		result.ComplianceStatus = "Skipped"
		result.Reason = "No bare metal nodes found"
		return result
	}

	var failures int

	for i := range bareMetalNodes {
		node := &bareMetalNodes[i]
		nodeName := node.Name

		// We need a pod running on this node to execute commands
		// Find a pod on this node (or use probe pod if available)
		var testPod *corev1.Pod
		for j := range resources.Pods {
			if resources.Pods[j].Spec.NodeName == nodeName {
				testPod = &resources.Pods[j]
				break
			}
		}

		if testPod == nil {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Node",
				Name:      nodeName,
				Compliant: false,
				Message:   "No pod found on node to execute hyperthread check",
			})
			failures++
			continue
		}

		// Check hyperthreading via lscpu
		// Command: lscpu | grep "Thread(s) per core"
		// If output is "2", hyperthreading is enabled
		command := "lscpu | grep 'Thread(s) per core' | awk '{print $NF}'"
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		stdout, stderr, err := resources.ProbeExecutor.ExecCommand(ctx, testPod, command)
		cancel()

		if err != nil || stderr != "" {
			failures++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Node",
				Name:      nodeName,
				Compliant: false,
				Message:   fmt.Sprintf("Failed to check hyperthreading: %v", err),
			})
			continue
		}

		threadsPerCore := strings.TrimSpace(stdout)
		if threadsPerCore != "2" {
			failures++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Node",
				Name:      nodeName,
				Compliant: false,
				Message:   fmt.Sprintf("Hyperthreading disabled (threads per core: %s)", threadsPerCore),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Node",
				Name:      nodeName,
				Compliant: true,
				Message:   "Hyperthreading enabled",
			})
		}
	}

	if failures > 0 {
		result.ComplianceStatus = "NonCompliant"
		result.Reason = fmt.Sprintf("%d bare metal node(s) do not have hyperthreading enabled", failures)
	}

	return result
}

func isBareMetalNode(node *corev1.Node) bool {
	// Check for absence of cloud provider labels
	// Common cloud provider labels include:
	// - node.kubernetes.io/instance-type
	// - topology.kubernetes.io/zone
	// - beta.kubernetes.io/instance-type
	// Bare metal nodes typically don't have these

	cloudLabels := []string{
		"node.kubernetes.io/instance-type",
		"beta.kubernetes.io/instance-type",
	}

	for _, label := range cloudLabels {
		if _, exists := node.Labels[label]; exists {
			return false
		}
	}

	return true
}
