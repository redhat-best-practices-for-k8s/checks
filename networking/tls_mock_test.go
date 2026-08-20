package networking

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

type mockPattern struct {
	key    string
	stdout string
	err    error
}

type containsProbeMock struct {
	patterns []mockPattern
	commands []string
}

func newContainsMock(patterns ...mockPattern) *containsProbeMock {
	return &containsProbeMock{patterns: patterns}
}

func (m *containsProbeMock) ExecCommandInContainer(ctx context.Context, pod *corev1.Pod, containerName, command string) (string, string, error) {
	return m.ExecCommand(ctx, pod, command)
}

func (m *containsProbeMock) ExecCommand(_ context.Context, _ *corev1.Pod, command string) (string, string, error) {
	m.commands = append(m.commands, command)
	for _, p := range m.patterns {
		if strings.Contains(command, p.key) {
			return p.stdout, "", p.err
		}
	}
	return "", "", fmt.Errorf("unexpected command: %s", command)
}

func probePod() *corev1.Pod {
	return &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "probe"}},
		},
	}
}
