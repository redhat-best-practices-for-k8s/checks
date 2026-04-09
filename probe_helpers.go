package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// GetContainerPID resolves the PID of a container by execing crictl inspect in the probe pod.
func GetContainerPID(ctx context.Context, executor ProbeExecutor, probePod *corev1.Pod, containerID string) (string, error) {
	cmd := fmt.Sprintf("chroot /host crictl inspect --output go-template --template '{{.info.pid}}' %s 2>/dev/null", containerID)
	stdout, _, err := executor.ExecCommand(ctx, probePod, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get PID for container %s: %w", containerID, err)
	}
	pid := strings.TrimSpace(stdout)
	if pid == "" {
		return "", fmt.Errorf("empty PID returned for container %s", containerID)
	}
	if _, err := strconv.Atoi(pid); err != nil {
		return "", fmt.Errorf("non-numeric PID %q returned for container %s", pid, containerID)
	}
	return pid, nil
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
