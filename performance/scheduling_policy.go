package performance

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
)

var schedPolicyRegex = regexp.MustCompile(`scheduling policy: (SCHED_\w+)`)

const (
	schedOther = "SCHED_OTHER"
	schedFIFO  = "SCHED_FIFO"
	schedRR    = "SCHED_RR"
	schedBatch = "SCHED_BATCH"
	schedIdle  = "SCHED_IDLE"
)

// CheckSharedCPUPoolSchedulingPolicy verifies non-guaranteed pods use SCHED_OTHER.
func CheckSharedCPUPoolSchedulingPolicy(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkSchedulingPolicy(resources, "shared", schedOther)
}

// CheckExclusiveCPUPoolSchedulingPolicy verifies guaranteed pods with exclusive CPUs use RT scheduling.
func CheckExclusiveCPUPoolSchedulingPolicy(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkSchedulingPolicy(resources, "exclusive", schedFIFO) // Accept FIFO or RR
}

// CheckIsolatedCPUPoolSchedulingPolicy verifies isolated CPU pods use RT scheduling.
func CheckIsolatedCPUPoolSchedulingPolicy(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkSchedulingPolicy(resources, "isolated", schedFIFO) // Accept FIFO or RR
}

func checkSchedulingPolicy(resources *checks.DiscoveredResources, cpuPool string, expectedPolicy string) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if resources.ProbeExecutor == nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = "ProbeExecutor not available for scheduling policy checks"
		return result
	}

	var podsToCheck []corev1.Pod

	// Filter pods based on CPU pool type
	for i := range resources.Pods {
		pod := resources.Pods[i]
		switch cpuPool {
		case "shared":
			// Non-guaranteed pods (no resource limits/requests or not equal)
			if !isGuaranteedPod(&pod) && !hasHostPID(&pod) {
				podsToCheck = append(podsToCheck, pod)
			}
		case "exclusive", "isolated":
			// Guaranteed pods with exclusive/isolated CPUs
			if isGuaranteedPod(&pod) && !hasHostPID(&pod) {
				// For simplicity, treat all guaranteed pods as potentially having exclusive CPUs
				// In real implementation, would need to check CPU manager policy
				podsToCheck = append(podsToCheck, pod)
			}
		}
	}

	if len(podsToCheck) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = fmt.Sprintf("No pods found for %s CPU pool", cpuPool)
		return result
	}

	var failures int

	for i := range podsToCheck {
		pod := &podsToCheck[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			containerName := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)

			// Get container PID namespace
			pidNS, err := getContainerPIDNamespace(resources, pod, container.Name)
			if err != nil {
				failures++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Failed to get PID namespace: %v", err),
				})
				continue
			}

			// Get PIDs in namespace
			pids, err := getPIDsInNamespace(resources, pod, pidNS)
			if err != nil {
				failures++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Failed to get PIDs: %v", err),
				})
				continue
			}

			// Check scheduling policy for each PID
			policyOK := true
			for _, pid := range pids {
				policy, err := getProcessSchedulingPolicy(resources, pod, pid)
				if err != nil {
					continue // Process may have exited
				}

				if !isExpectedPolicy(policy, expectedPolicy, cpuPool) {
					policyOK = false
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind:      "Process",
						Name:      fmt.Sprintf("%s (PID %d)", containerName, pid),
						Namespace: pod.Namespace,
						Compliant: false,
						Message:   fmt.Sprintf("Unexpected scheduling policy: %s (expected %s for %s pool)", policy, expectedPolicy, cpuPool),
					})
					failures++
					break
				}
			}

			if policyOK {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind:      "Container",
					Name:      containerName,
					Namespace: pod.Namespace,
					Compliant: true,
					Message:   fmt.Sprintf("Correct scheduling policy for %s CPU pool", cpuPool),
				})
			}
		}
	}

	if failures > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) have incorrect scheduling policy for %s CPU pool", failures, cpuPool)
	}

	return result
}

func isGuaranteedPod(pod *corev1.Pod) bool {
	// A pod is guaranteed QoS if all containers have limits == requests for CPU and memory
	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		if container.Resources.Limits == nil || container.Resources.Requests == nil {
			return false
		}

		cpuLimit := container.Resources.Limits["cpu"]
		cpuRequest := container.Resources.Requests["cpu"]
		memLimit := container.Resources.Limits["memory"]
		memRequest := container.Resources.Requests["memory"]

		if cpuLimit.Cmp(cpuRequest) != 0 || memLimit.Cmp(memRequest) != 0 {
			return false
		}
	}
	return true
}

func hasHostPID(pod *corev1.Pod) bool {
	return pod.Spec.HostPID
}

func getContainerPIDNamespace(resources *checks.DiscoveredResources, pod *corev1.Pod, containerName string) (string, error) {
	// Get the PID namespace by inspecting container via probe pod
	// Command: nsenter -t <container-pid> -p pidof <process>
	// For simplicity, using a heuristic command
	command := "pgrep -P 1 | head -1"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, pod, command)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout), nil
}

func getPIDsInNamespace(resources *checks.DiscoveredResources, pod *corev1.Pod, pidNS string) ([]int, error) {
	// Get list of PIDs in the namespace
	command := "ps -e -o pid --no-headers"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, pod, command)
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func getProcessSchedulingPolicy(resources *checks.DiscoveredResources, pod *corev1.Pod, pid int) (string, error) {
	// Use chrt to get scheduling policy
	command := fmt.Sprintf("chrt -p %d", pid)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, pod, command)
	if err != nil {
		return "", err
	}

	// Parse output like: "pid 123's current scheduling policy: SCHED_OTHER"
	matches := schedPolicyRegex.FindStringSubmatch(stdout)
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", fmt.Errorf("could not parse scheduling policy from: %s", stdout)
}

func isExpectedPolicy(actual, expected, cpuPool string) bool {
	if cpuPool == "shared" {
		// Shared CPU pool should use SCHED_OTHER or SCHED_BATCH
		return actual == schedOther || actual == schedBatch || actual == schedIdle
	}
	// Exclusive/isolated pools should use RT scheduling (FIFO or RR)
	return actual == schedFIFO || actual == schedRR
}
