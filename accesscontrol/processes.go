package accesscontrol

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
)

const nbProcessesIndex = 2

// CheckOneProcess verifies each container runs only one process (probe-based).
// It uses crictl inspect to get the container PID, then lsns to count processes
// in the container's PID namespace.
func CheckOneProcess(resources *checks.DiscoveredResources) checks.CheckResult {
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

	for i := range resources.Pods {
		pod := &resources.Pods[i]
		probePod, ok := resources.ProbePods[pod.Spec.NodeName]
		if !ok || probePod == nil {
			continue
		}

		for j := range pod.Status.ContainerStatuses {
			containerName := pod.Status.ContainerStatuses[j].Name

			// Skip istio-proxy sidecar containers
			if checks.IsIgnoredContainer(containerName) {
				continue
			}

			containerID := checks.ParseContainerID(pod.Status.ContainerStatuses[j].ContainerID)
			if containerID == "" {
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			pid, err := checks.GetContainerPID(ctx, resources.ProbeExecutor, probePod, containerID)
			if err != nil {
				cancel()
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q: failed to get PID: %v", containerName, err),
				})
				continue
			}

			lsnsCmd := fmt.Sprintf("lsns -p %s -t pid -n", pid)
			stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, probePod, lsnsCmd)
			cancel()
			if err != nil {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q: failed to run lsns: %v", containerName, err),
				})
				continue
			}

			fields := strings.Fields(strings.TrimSpace(stdout))
			if len(fields) <= nbProcessesIndex {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q: unexpected lsns output: %s", containerName, stdout),
				})
				continue
			}

			nbProcesses, err := strconv.Atoi(fields[nbProcessesIndex])
			if err != nil {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q: failed to parse NPROCS: %v", containerName, err),
				})
				continue
			}

			if nbProcesses > 1 {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Container %q has %d processes running", containerName, nbProcesses),
				})
			} else {
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: true,
					Message:   fmt.Sprintf("Container %q has only one process running", containerName),
				})
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) have multiple processes", count)
	}
	return result
}

// CheckNoSSHD verifies no SSH daemons are running in any container (probe-based).
// It uses crictl inspect to get the container PID, then nsenter + ss to check
// for sshd listening in the container's network namespace.
func CheckNoSSHD(resources *checks.DiscoveredResources) checks.CheckResult {
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

	for i := range resources.Pods {
		pod := &resources.Pods[i]
		probePod, ok := resources.ProbePods[pod.Spec.NodeName]
		if !ok || probePod == nil {
			continue
		}

		// Check the first container of the pod (same as certsuite)
		if len(pod.Status.ContainerStatuses) == 0 {
			continue
		}

		containerID := checks.ParseContainerID(pod.Status.ContainerStatuses[0].ContainerID)
		if containerID == "" {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		pid, err := checks.GetContainerPID(ctx, resources.ProbeExecutor, probePod, containerID)
		if err != nil {
			cancel()
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Failed to get container PID: %v", err),
			})
			continue
		}

		ssCmd := fmt.Sprintf("nsenter -t %s -n ss -tpln", pid)
		stdout, _, err := resources.ProbeExecutor.ExecCommand(ctx, probePod, ssCmd)
		cancel()
		if err != nil {
			// If the command fails, we cannot determine compliance
			continue
		}

		if strings.Contains(stdout, "sshd") {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false, Message: "SSH daemon found running",
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: true, Message: "No SSH daemon running",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) have SSH daemons running", count)
	}
	return result
}
