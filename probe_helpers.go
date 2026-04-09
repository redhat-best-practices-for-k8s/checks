package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

const (
	pidRetryAttempts = 5
	pidRetrySleep    = 3 * time.Second
)

// GetContainerPID resolves the PID of a container by execing crictl inspect in the probe pod.
// Includes retry logic matching the certsuite's ExecCommandContainerNSEnter behavior.
func GetContainerPID(ctx context.Context, executor ProbeExecutor, probePod *corev1.Pod, containerID string) (string, error) {
	cmd := fmt.Sprintf("chroot /host crictl inspect --output go-template --template '{{.info.pid}}' %s 2>/dev/null", containerID)
	var lastErr error
	for attempt := 1; attempt <= pidRetryAttempts; attempt++ {
		stdout, _, err := executor.ExecCommand(ctx, probePod, cmd)
		if err != nil {
			lastErr = err
			if attempt < pidRetryAttempts {
				time.Sleep(pidRetrySleep)
			}
			continue
		}
		pid := strings.TrimSpace(stdout)
		if pid == "" {
			lastErr = fmt.Errorf("empty PID returned for container %s", containerID)
			if attempt < pidRetryAttempts {
				time.Sleep(pidRetrySleep)
			}
			continue
		}
		if _, err := strconv.Atoi(pid); err != nil {
			return "", fmt.Errorf("non-numeric PID %q returned for container %s", pid, containerID)
		}
		return pid, nil
	}
	return "", fmt.Errorf("failed to get PID for container %s after %d attempts: %w", containerID, pidRetryAttempts, lastErr)
}

// ParseContainerID extracts the runtime container ID from a ContainerStatus.ContainerID
// string (e.g., "cri-o://abc123" -> "abc123").
func ParseContainerID(rawID string) string {
	parts := strings.SplitN(rawID, "://", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return rawID
}
