package testutil

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// MockProbeResponse holds the response for a mocked probe command.
type MockProbeResponse struct {
	Stdout string
	Stderr string
	Err    error
}

// MockProbeExecutor is a test implementation of checks.ProbeExecutor.
type MockProbeExecutor struct {
	// Responses maps command strings to their expected responses.
	// You can also use command prefixes if you set PrefixMatch to true.
	Responses map[string]MockProbeResponse

	// PrefixMatch enables matching commands by prefix instead of exact match.
	PrefixMatch bool

	// CommandLog records all commands that were executed.
	CommandLog []string
}

// ExecCommand implements the ProbeExecutor interface for testing.
func (m *MockProbeExecutor) ExecCommand(_ context.Context, pod *corev1.Pod, command string) (string, string, error) {
	if m.CommandLog != nil {
		m.CommandLog = append(m.CommandLog, command)
	}

	// Try exact match first
	if r, ok := m.Responses[command]; ok {
		return r.Stdout, r.Stderr, r.Err
	}

	// Try prefix match if enabled
	if m.PrefixMatch {
		for prefix, r := range m.Responses {
			if len(command) >= len(prefix) && command[:len(prefix)] == prefix {
				return r.Stdout, r.Stderr, r.Err
			}
		}
	}

	// No match found
	return "", "", fmt.Errorf("mock: unexpected command: %s", command)
}

// NewMockProbeExecutor creates a new MockProbeExecutor with the given responses.
func NewMockProbeExecutor(responses map[string]MockProbeResponse) *MockProbeExecutor {
	return &MockProbeExecutor{
		Responses:   responses,
		CommandLog:  make([]string, 0),
		PrefixMatch: false,
	}
}

// NewMockK8sClient creates a fake Kubernetes clientset for testing.
// You can pre-populate it with objects by passing them as arguments.
func NewMockK8sClient(objects ...runtime.Object) kubernetes.Interface {
	//nolint:staticcheck // NewSimpleClientset is the standard way to create test clients
	return fake.NewSimpleClientset(objects...)
}
