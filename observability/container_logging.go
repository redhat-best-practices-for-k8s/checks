package observability

import (
	"context"
	"fmt"
	"io"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckContainerLogging verifies that all containers produce logging output to stdout/stderr.
func CheckContainerLogging(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if resources.K8sClientset == nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = "Kubernetes client not available"
		return result
	}

	// Type assert the interface to kubernetes.Interface
	k8sClient, ok := resources.K8sClientset.(kubernetes.Interface)
	if !ok {
		result.ComplianceStatus = checks.StatusError
		result.Reason = "K8sClientset is not a valid kubernetes.Interface"
		return result
	}

	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var failedContainers int

	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			containerName := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)

			hasLogs, err := containerHasLoggingOutput(k8sClient, pod, container.Name)
			if err != nil {
				failedContainers++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Failed to get log output: %v", err),
				})
				continue
			}

			if !hasLogs {
				failedContainers++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   "No log lines found in stdout/stderr",
				})
			} else {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: true,
					Message:   "Container has logging output",
				})
			}
		}
	}

	if failedContainers > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) do not produce logging output", failedContainers)
	}

	return result
}

// containerHasLoggingOutput checks if a container has any logging output.
// Returns true if at least one log line is found, false otherwise.
func containerHasLoggingOutput(client kubernetes.Interface, pod *corev1.Pod, containerName string) (bool, error) {
	// Request the last 2 lines (K8s API won't return lines without newline termination)
	tailLines := int64(2)
	podLogOptions := &corev1.PodLogOptions{
		TailLines: &tailLines,
		Container: containerName,
	}

	req := client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, podLogOptions)
	podLogsReaderCloser, err := req.Stream(context.Background())
	if err != nil {
		return false, fmt.Errorf("unable to get log stream: %v", err)
	}
	defer func() {
		_ = podLogsReaderCloser.Close()
	}()

	// Read all log data
	logData, err := io.ReadAll(podLogsReaderCloser)
	if err != nil {
		return false, fmt.Errorf("unable to read log data: %v", err)
	}

	// Check if there's any content
	return len(logData) > 0, nil
}
