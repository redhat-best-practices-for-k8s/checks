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
	testPairs := buildICMPTestPairs(resources.Pods, ipVersion, multus, resources.PodMultusNetworks)

	if len(testPairs) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = fmt.Sprintf("No IPv%s addresses found for testing", ipVersion)
		return result
	}

	var failures int

	// Cache resolved PIDs by source pod key to avoid repeated lookups.
	type resolvedSource struct {
		pid      string
		probePod *corev1.Pod
	}
	pidCache := make(map[string]*resolvedSource)

	for _, pair := range testPairs {
		sourceKey := pair.sourcePod.Namespace + "/" + pair.sourcePod.Name

		rs, cached := pidCache[sourceKey]
		if !cached {
			probePod, ok := resources.ProbePods[pair.sourcePod.Spec.NodeName]
			if !ok || probePod == nil {
				failures++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "ICMPTest",
					Name:      fmt.Sprintf("%s->%s", pair.sourcePod.Name, pair.targetPod.Name),
					Namespace: pair.sourcePod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("No probe pod available on node %s", pair.sourcePod.Spec.NodeName),
				})
				continue
			}
			if len(pair.sourcePod.Status.ContainerStatuses) == 0 {
				failures++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "ICMPTest",
					Name:      fmt.Sprintf("%s->%s", pair.sourcePod.Name, pair.targetPod.Name),
					Namespace: pair.sourcePod.Namespace,
					Compliant: false,
					Message:   "Source pod has no container statuses",
				})
				continue
			}
			containerID := checks.ParseContainerID(pair.sourcePod.Status.ContainerStatuses[0].ContainerID)
			pidCtx, pidCancel := context.WithTimeout(context.Background(), 30*time.Second)
			sourcePID, err := checks.GetContainerPID(pidCtx, resources.ProbeExecutor, probePod, containerID)
			pidCancel()
			if err != nil {
				failures++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "ICMPTest",
					Name:      fmt.Sprintf("%s->%s", pair.sourcePod.Name, pair.targetPod.Name),
					Namespace: pair.sourcePod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Failed to get source container PID: %v", err),
				})
				continue
			}
			rs = &resolvedSource{pid: sourcePID, probePod: probePod}
			pidCache[sourceKey] = rs
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		var pingCmd string
		if pair.interfaceName != "" {
			pingCmd = fmt.Sprintf("nsenter -t %s -n ping -I %s -c %d %s", rs.pid, pair.interfaceName, defaultPingCount, pair.targetIP)
		} else {
			pingCmd = fmt.Sprintf("nsenter -t %s -n ping -c %d %s", rs.pid, defaultPingCount, pair.targetIP)
		}
		stdout, stderr, err := resources.ProbeExecutor.ExecCommand(ctx, rs.probePod, pingCmd)
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
	sourcePod     *corev1.Pod
	targetPod     *corev1.Pod
	targetIP      string
	interfaceName string // Multus interface name on the source pod (e.g. "net1"); empty for default network
}

const (
	skipConnectivityLabel      = "redhat-best-practices-for-k8s.com/skip_connectivity_tests"
	skipMultusConnectivityLabel = "redhat-best-practices-for-k8s.com/skip_multus_connectivity_tests"
)

func buildICMPTestPairs(pods []corev1.Pod, ipVersion string, multus bool, podMultusNetworks ...map[string][]checks.MultusNetwork) []icmpTestPair {
	if multus {
		var mn map[string][]checks.MultusNetwork
		if len(podMultusNetworks) > 0 {
			mn = podMultusNetworks[0]
		}
		return buildMultusICMPTestPairs(pods, ipVersion, mn)
	}
	return buildDefaultICMPTestPairs(pods, ipVersion)
}

func buildDefaultICMPTestPairs(pods []corev1.Pod, ipVersion string) []icmpTestPair {
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

		// Use pod IP from status
		var targetIP string
		for _, podIP := range targetPod.Status.PodIPs {
			if ipVersion == "4" && isIPv4(podIP.IP) {
				targetIP = podIP.IP
				break
			} else if ipVersion == "6" && !isIPv4(podIP.IP) {
				targetIP = podIP.IP
				break
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

// multusNetPod associates a pod with its Multus interface name and IPs on a specific network.
type multusNetPod struct {
	pod           *corev1.Pod
	interfaceName string
	ips           []string // IPs filtered by version
}

func buildMultusICMPTestPairs(pods []corev1.Pod, ipVersion string, podMultusNetworks map[string][]checks.MultusNetwork) []icmpTestPair {
	var pairs []icmpTestPair

	if podMultusNetworks == nil {
		return pairs
	}

	// Filter out pods with skip_connectivity_tests or skip_multus_connectivity_tests labels
	var filtered []corev1.Pod
	for i := range pods {
		if _, skip := pods[i].Labels[skipConnectivityLabel]; skip {
			continue
		}
		if _, skip := pods[i].Labels[skipMultusConnectivityLabel]; skip {
			continue
		}
		filtered = append(filtered, pods[i])
	}

	// Group pods by Multus network name
	// networkName -> []multusNetPod
	type netEntry = []multusNetPod
	networks := make(map[string]netEntry)

	for i := range filtered {
		pod := &filtered[i]
		podKey := pod.Namespace + "/" + pod.Name
		multusNets, ok := podMultusNetworks[podKey]
		if !ok {
			continue
		}
		for _, mn := range multusNets {
			filteredIPs := filterIPsByVersion(mn.IPs, ipVersion)
			if len(filteredIPs) == 0 {
				continue
			}
			networks[mn.Name] = append(networks[mn.Name], multusNetPod{
				pod:           pod,
				interfaceName: mn.InterfaceName,
				ips:           filteredIPs,
			})
		}
	}

	// For each network with 2+ pods, create test pairs:
	// first pod = source, all others = targets
	for _, netPods := range networks {
		if len(netPods) < 2 {
			continue
		}
		source := netPods[0]
		for _, target := range netPods[1:] {
			for _, ip := range target.ips {
				pairs = append(pairs, icmpTestPair{
					sourcePod:     source.pod,
					targetPod:     target.pod,
					targetIP:      ip,
					interfaceName: source.interfaceName,
				})
			}
		}
	}

	return pairs
}

// filterIPsByVersion returns only IPs matching the given version ("4" or "6").
func filterIPsByVersion(ips []string, ipVersion string) []string {
	var filtered []string
	for _, ip := range ips {
		if ipVersion == "4" && isIPv4(ip) {
			filtered = append(filtered, ip)
		} else if ipVersion == "6" && !isIPv4(ip) {
			filtered = append(filtered, ip)
		}
	}
	return filtered
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
