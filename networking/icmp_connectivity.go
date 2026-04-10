package networking

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
)

const (
	defaultPingCount = 5
	// SuccessfulOutputRegex matches a successfully run "ping" command.
	successfulOutputRegex = `(?m)(\d+) packets transmitted, (\d+)( packets){0,1} received, (?:\+(\d+) errors)?.*$`
)

var (
	pingOutputRegex = regexp.MustCompile(successfulOutputRegex)
	ipv6Regex       = regexp.MustCompile(`:`)
)

type pingResult struct {
	transmitted int
	received    int
	errors      int
	success     bool
}

// CheckICMPv4Connectivity verifies IPv4 ICMP connectivity between pods on default network.
func CheckICMPv4Connectivity(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkICMPConnectivity(resources, "4", false)
}

// CheckICMPv6Connectivity verifies IPv6 ICMP connectivity between pods on default network.
func CheckICMPv6Connectivity(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkICMPConnectivity(resources, "6", false)
}

// CheckICMPv4ConnectivityMultus verifies IPv4 ICMP connectivity between pods on Multus networks.
func CheckICMPv4ConnectivityMultus(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkICMPConnectivity(resources, "4", true)
}

// CheckICMPv6ConnectivityMultus verifies IPv6 ICMP connectivity between pods on Multus networks.
func CheckICMPv6ConnectivityMultus(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkICMPConnectivity(resources, "6", true)
}

func checkICMPConnectivity(resources *checks.DiscoveredResources, ipVersion string, multus bool) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if resources.ProbeExecutor == nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = "ProbeExecutor not available for ICMP connectivity checks"
		return result
	}

	if len(resources.ProbePods) == 0 {
		result.ComplianceStatus = checks.StatusError
		result.Reason = "No probe pods available for ICMP connectivity checks"
		return result
	}

	if len(resources.Pods) < 2 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "At least 2 pods required for ICMP connectivity testing"
		return result
	}

	// Build test pairs: source pod -> target pod IPs
	testPairs := buildICMPTestPairs(resources.Pods, ipVersion, multus)

	if len(testPairs) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = fmt.Sprintf("No IPv%s addresses found for testing", ipVersion)
		return result
	}

	var failures int

	// All pairs share the same source pod -- resolve its PID once.
	sourcePod := testPairs[0].sourcePod
	probePod, ok := resources.ProbePods[sourcePod.Spec.NodeName]
	if !ok || probePod == nil {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("No probe pod available on node %s", sourcePod.Spec.NodeName)
		return result
	}
	if len(sourcePod.Status.ContainerStatuses) == 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = "Source pod has no container statuses"
		return result
	}
	containerID := checks.ParseContainerID(sourcePod.Status.ContainerStatuses[0].ContainerID)
	pidCtx, pidCancel := context.WithTimeout(context.Background(), 30*time.Second)
	sourcePID, err := checks.GetContainerPID(pidCtx, resources.ProbeExecutor, probePod, containerID)
	pidCancel()
	if err != nil {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("Failed to get source container PID: %v", err)
		return result
	}

	for _, pair := range testPairs {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		pingCmd := fmt.Sprintf("nsenter -t %s -n ping -c %d %s", sourcePID, defaultPingCount, pair.targetIP)
		stdout, stderr, err := resources.ProbeExecutor.ExecCommand(ctx, probePod, pingCmd)
		cancel()

		if err != nil || stderr != "" {
			failures++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "ICMPTest",
				Name:      fmt.Sprintf("%s->%s", pair.sourcePod.Name, pair.targetPod.Name),
				Namespace: pair.sourcePod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Ping failed: %v", err),
			})
			continue
		}

		pingRes := parsePingOutput(stdout)
		if !pingRes.success {
			failures++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "ICMPTest",
				Name:      fmt.Sprintf("%s->%s", pair.sourcePod.Name, pair.targetPod.Name),
				Namespace: pair.sourcePod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Ping unsuccessful: %d/%d packets received", pingRes.received, pingRes.transmitted),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "ICMPTest",
				Name:      fmt.Sprintf("%s->%s", pair.sourcePod.Name, pair.targetPod.Name),
				Namespace: pair.sourcePod.Namespace,
				Compliant: true,
				Message:   "ICMP connectivity successful",
			})
		}
	}

	if failures > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d ICMP connectivity test(s) failed", failures)
	}

	return result
}

type icmpTestPair struct {
	sourcePod *corev1.Pod
	targetPod *corev1.Pod
	targetIP  string
}

const (
	skipConnectivityLabel = "redhat-best-practices-for-k8s.com/skip_connectivity_tests"
)

func buildICMPTestPairs(pods []corev1.Pod, ipVersion string, multus bool) []icmpTestPair {
	var pairs []icmpTestPair

	// Filter out pods with the skip_connectivity_tests label
	var filtered []corev1.Pod
	for i := range pods {
		if _, skip := pods[i].Labels[skipConnectivityLabel]; skip {
			continue
		}
		filtered = append(filtered, pods[i])
	}

	if len(filtered) < 2 {
		return pairs
	}

	sourcePod := &filtered[0]

	for i := 1; i < len(filtered); i++ {
		targetPod := &filtered[i]

		// Get appropriate IP address
		var targetIP string
		if multus {
			// TODO: Extract Multus network IPs when available in DiscoveredResources
			continue
		} else {
			// Use pod IP from status
			for _, podIP := range targetPod.Status.PodIPs {
				if ipVersion == "4" && isIPv4(podIP.IP) {
					targetIP = podIP.IP
					break
				} else if ipVersion == "6" && !isIPv4(podIP.IP) {
					targetIP = podIP.IP
					break
				}
			}
		}

		if targetIP != "" {
			pairs = append(pairs, icmpTestPair{
				sourcePod: sourcePod,
				targetPod: targetPod,
				targetIP:  targetIP,
			})
		}
	}

	return pairs
}

func parsePingOutput(stdout string) pingResult {
	result := pingResult{}

	matches := pingOutputRegex.FindStringSubmatch(stdout)

	if matches == nil {
		return result
	}

	result.transmitted, _ = strconv.Atoi(matches[1])
	result.received, _ = strconv.Atoi(matches[2])
	if len(matches) > 4 {
		result.errors, _ = strconv.Atoi(matches[4])
	}

	// Success if we received responses and packet loss is acceptable (<=1 packet lost)
	result.success = result.received > 0 && (result.transmitted-result.received) <= 1 && result.errors == 0

	return result
}

func isIPv4(ip string) bool {
	// Simple check: IPv4 addresses don't contain colons
	return !ipv6Regex.MatchString(ip)
}
