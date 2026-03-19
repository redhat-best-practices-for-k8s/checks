package platform

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// NodeCheckResult contains the result of checking a single node via probe.
type NodeCheckResult struct {
	// Violations contains non-compliant findings for this node
	Violations []checks.ResourceDetail
	// Failed indicates whether probe execution failed (vs finding violations)
	Failed bool
	// FailureMessage is the error message if Failed is true
	FailureMessage string
}

// NodeCheckFunc is called once per node to perform the actual check logic.
// It should execute probe commands and return violations or mark as failed.
type NodeCheckFunc func(ctx context.Context, nodeName string, probePod *corev1.Pod, executor checks.ProbeExecutor) NodeCheckResult

// ExecuteProbeCheck executes a probe-based check across all probe pods.
// It handles the common boilerplate:
// - Checking probe availability
// - Creating context with timeout
// - Looping through probe pods
// - Collecting violations and failures
// - Building the final result with appropriate reason
//
// The checkFunc parameter contains the node-specific validation logic.
// The violationReasonTemplate should be a format string with one %d placeholder
// for the violation count (e.g., "%d node(s) have tainted kernels").
func ExecuteProbeCheck(
	resources *checks.DiscoveredResources,
	checkFunc NodeCheckFunc,
	violationReasonTemplate string,
) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	// Check probe availability
	if resources.ProbeExecutor == nil || len(resources.ProbePods) == 0 {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "Probe pods not available"
		return result
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Track violations and failures
	var violationCount int
	var failedNodes []string

	// Execute check on each node
	for nodeName, probePod := range resources.ProbePods {
		nodeResult := checkFunc(ctx, nodeName, probePod, resources.ProbeExecutor)

		// Handle probe execution failure
		if nodeResult.Failed {
			failedNodes = append(failedNodes, nodeName)
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Node",
				Name:      nodeName,
				Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("Failed to execute probe command: %v", nodeResult.FailureMessage),
			})
			continue
		}

		// Collect violations
		if len(nodeResult.Violations) > 0 {
			violationCount += len(nodeResult.Violations)
			result.Details = append(result.Details, nodeResult.Violations...)
		}
	}

	// Build final result
	if violationCount > 0 || len(failedNodes) > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		if violationCount > 0 && len(failedNodes) > 0 {
			result.Reason = fmt.Sprintf(violationReasonTemplate+"; %d node(s) failed probe execution", violationCount, len(failedNodes))
		} else if violationCount > 0 {
			result.Reason = fmt.Sprintf(violationReasonTemplate, violationCount)
		} else {
			result.Reason = fmt.Sprintf("%d node(s) failed probe execution", len(failedNodes))
		}
	}

	return result
}
