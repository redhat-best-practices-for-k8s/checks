package networking

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

const (
	getListeningPortsCmd = `ss -tulwnH`
	portStateListen      = "LISTEN"
	indexProtocol        = 0
	indexState           = 1
	indexPort            = 4
)

var reservedIstioPorts = map[int32]bool{
	// https://istio.io/latest/docs/ops/deployment/requirements/#ports-used-by-istio
	15090: true, // Envoy Prometheus telemetry
	15053: true, // DNS port, if capture is enabled
	15021: true, // Health checks
	15020: true, // Merged Prometheus telemetry from Istio agent, Envoy, and application
	15009: true, // HBONE port for secure networks
	15008: true, // HBONE mTLS tunnel port
	15006: true, // Envoy inbound
	15004: true, // Debug port
	15001: true, // Envoy outbound
	15000: true, // Envoy admin port
}

type portInfo struct {
	PortNumber int32
	Protocol   string
}

// CheckUndeclaredContainerPorts verifies all listening ports are declared in container specs.
func CheckUndeclaredContainerPorts(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if resources.ProbeExecutor == nil || len(resources.ProbePods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "Probe pods not available"
		return result
	}

	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := range resources.Pods {
		pod := &resources.Pods[i]

		// Get probe pod for this node
		probePod, ok := resources.ProbePods[pod.Spec.NodeName]
		if !ok || probePod == nil {
			continue
		}

		// Build map of declared ports
		declaredPorts := make(map[portInfo]bool)
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				pi := portInfo{
					PortNumber: port.ContainerPort,
					Protocol:   string(port.Protocol),
				}
				declaredPorts[pi] = true
			}
		}

		// Get listening ports by executing ss command
		if len(pod.Spec.Containers) == 0 {
			continue
		}

		// Execute ss command to get listening ports
		listeningPorts, err := getListeningPorts(ctx, resources.ProbeExecutor, probePod, pod)
		if err != nil {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Failed to get listening ports: %v", err),
			})
			count++
			continue
		}

		// If no ports are listening, that's compliant
		if len(listeningPorts) == 0 {
			continue
		}

		// Check if pod contains istio-proxy
		hasIstioProxy := containsIstioProxy(pod)

		// Compare listening ports with declared ports
		hasUndeclaredPorts := false
		for listeningPort := range listeningPorts {
			// Skip Istio reserved ports if istio-proxy is present
			if hasIstioProxy && reservedIstioPorts[listeningPort.PortNumber] {
				continue
			}

			// Check if port was declared
			if !declaredPorts[listeningPort] {
				hasUndeclaredPorts = true
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Listening on undeclared port %d (%s)", listeningPort.PortNumber, listeningPort.Protocol),
				})
			}
		}

		if hasUndeclaredPorts {
			count++
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Compliant: true,
				Message:   "All listening ports are declared in container spec",
			})
		}
	}

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) have undeclared listening ports", count)
	}

	return result
}

// getListeningPorts resolves the container PID and runs ss in its network namespace.
func getListeningPorts(ctx context.Context, executor checks.ProbeExecutor, probePod *corev1.Pod, targetPod *corev1.Pod) (map[portInfo]bool, error) {
	if len(targetPod.Status.ContainerStatuses) == 0 {
		return nil, fmt.Errorf("no container statuses for pod %s/%s", targetPod.Namespace, targetPod.Name)
	}
	containerID := checks.ParseContainerID(targetPod.Status.ContainerStatuses[0].ContainerID)
	if containerID == "" {
		return nil, fmt.Errorf("empty container ID for pod %s/%s", targetPod.Namespace, targetPod.Name)
	}

	pid, err := checks.GetContainerPID(ctx, executor, probePod, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get container PID: %w", err)
	}

	cmd := fmt.Sprintf("nsenter -t %s -n %s", pid, getListeningPortsCmd)
	stdout, _, err := executor.ExecCommand(ctx, probePod, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ss command: %w", err)
	}

	return parseListeningPorts(stdout)
}

// parseListeningPorts parses the output of ss command
func parseListeningPorts(cmdOut string) (map[portInfo]bool, error) {
	portSet := make(map[portInfo]bool)

	cmdOut = strings.TrimSuffix(cmdOut, "\n")
	if cmdOut == "" {
		return portSet, nil
	}

	lines := strings.Split(cmdOut, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < indexPort+1 {
			continue
		}
		if fields[indexState] != portStateListen {
			continue
		}

		// Extract port from address field (format: [::]:port or 0.0.0.0:port)
		s := strings.Split(fields[indexPort], ":")
		if len(s) == 0 {
			continue
		}

		portStr := s[len(s)-1]
		port, err := strconv.ParseInt(portStr, 10, 32)
		if err != nil {
			continue // Skip unparseable ports
		}

		protocol := strings.ToUpper(fields[indexProtocol])
		pi := portInfo{
			PortNumber: int32(port),
			Protocol:   protocol,
		}

		portSet[pi] = true
	}

	return portSet, nil
}

func containsIstioProxy(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if checks.IsIgnoredContainer(container.Name) {
			return true
		}
	}
	return false
}
