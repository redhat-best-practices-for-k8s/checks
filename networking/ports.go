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
	istioProxyContainer  = "istio-proxy"
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
		}
	}

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) have undeclared listening ports", count)
	}

	return result
}

// getContainerIDFromPod extracts the container runtime ID from the pod's container statuses.
// The container ID in the status has the format "runtime://hash", and we return just the hash.
func getContainerIDFromPod(pod *corev1.Pod) (string, error) {
	if len(pod.Status.ContainerStatuses) == 0 {
		return "", fmt.Errorf("no container statuses found for pod %s/%s", pod.Namespace, pod.Name)
	}

	// Use the first container's status to get its ID (same approach as certsuite)
	containerID := pod.Status.ContainerStatuses[0].ContainerID
	parts := strings.SplitN(containerID, "://", 2)
	if len(parts) < 2 || parts[1] == "" {
		return "", fmt.Errorf("could not parse container ID %q for pod %s/%s", containerID, pod.Namespace, pod.Name)
	}

	return parts[1], nil
}

// getListeningPorts executes ss command and parses output to get listening ports
func getListeningPorts(ctx context.Context, executor checks.ProbeExecutor, probePod *corev1.Pod, targetPod *corev1.Pod) (map[portInfo]bool, error) {
	// Get the container ID from the pod's container status (pod-scoped, not name-based)
	containerID, err := getContainerIDFromPod(targetPod)
	if err != nil {
		return nil, fmt.Errorf("failed to get container ID: %w", err)
	}

	// Get the PID of the container using crictl inspect with the container ID
	getPIDCmd := fmt.Sprintf("chroot /host crictl inspect --output go-template --template '{{.info.pid}}' %s 2>/dev/null", containerID)
	pidOut, _, err := executor.ExecCommand(ctx, probePod, getPIDCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get container PID: %w", err)
	}

	pidOut = strings.TrimSpace(pidOut)
	if pidOut == "" || pidOut == "null" || pidOut == "0" {
		return nil, fmt.Errorf("could not determine PID for container %s in pod %s/%s", containerID, targetPod.Namespace, targetPod.Name)
	}

	// Execute ss command in the container's network namespace using nsenter with -n (network namespace only)
	cmd := fmt.Sprintf("nsenter -t %s -n %s", pidOut, getListeningPortsCmd)
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

// containsIstioProxy checks if pod has istio-proxy container
func containsIstioProxy(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name == istioProxyContainer {
			return true
		}
	}
	return false
}
