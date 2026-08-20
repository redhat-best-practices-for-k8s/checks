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

const nonTLSPortsAnnotation = "certsuite.redhat.com/non-tls-ports"

func parseNonTLSPortsAnnotation(pod *corev1.Pod) map[int32]bool {
	exempt := make(map[int32]bool)
	if pod.Annotations == nil {
		return exempt
	}
	ann, ok := pod.Annotations[nonTLSPortsAnnotation]
	if !ok || ann == "" {
		return exempt
	}
	for _, p := range strings.Split(ann, ",") {
		p = strings.TrimSpace(p)
		port, err := strconv.ParseInt(p, 10, 32)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		exempt[int32(port)] = true
	}
	return exempt
}

// CheckUnsecuredContainerPorts verifies listening TCP ports use TLS encryption.
func CheckUnsecuredContainerPorts(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if resources.ProbeExecutor == nil || firstProbePod(resources) == nil {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "Probe pods not available"
		return result
	}

	if len(resources.Pods) == 0 {
		result.Reason = "No pods found"
		return result
	}

	opensslProbe := firstProbePod(resources)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var nonCompliant int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		probePod, ok := resources.ProbePods[pod.Spec.NodeName]
		if !ok || probePod == nil {
			continue
		}
		if len(pod.Spec.Containers) == 0 {
			continue
		}

		listeningPorts, err := getListeningPorts(ctx, resources.ProbeExecutor, probePod, pod)
		if err != nil {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Failed to get listening ports: %v", err),
			})
			nonCompliant++
			continue
		}

		if len(listeningPorts) == 0 {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Compliant: true,
				Message:   "No listening ports",
			})
			continue
		}

		podIP := pod.Status.PodIP
		if podIP == "" {
			continue
		}

		exemptPorts := parseNonTLSPortsAnnotation(pod)
		hasIstioProxy := containsIstioProxy(pod)
		podFailed := false

		for port := range listeningPorts {
			if port.Protocol != "TCP" {
				continue
			}
			if hasIstioProxy && reservedIstioPorts[port.PortNumber] {
				continue
			}
			if exemptPorts[port.PortNumber] {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Compliant: true,
					Message:   fmt.Sprintf("Port %d exempt via annotation", port.PortNumber),
				})
				continue
			}

			isTLS, reachable, reason := IsPortTLS(ctx, resources.ProbeExecutor, opensslProbe, podIP, port.PortNumber)
			switch {
			case !reachable:
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Compliant: true,
					Message:   fmt.Sprintf("Port %d unreachable (%s)", port.PortNumber, reason),
				})
			case isTLS:
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Compliant: true,
					Message:   fmt.Sprintf("Port %d uses TLS (%s)", port.PortNumber, reason),
				})
			default:
				podFailed = true
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Port %d accepts plaintext connections (%s)", port.PortNumber, reason),
				})
			}
		}

		if podFailed {
			nonCompliant++
		}
	}

	if nonCompliant > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) have unsecured TCP ports", nonCompliant)
		return result
	}

	result.Reason = "All listening TCP ports use TLS or are exempt"
	return result
}
