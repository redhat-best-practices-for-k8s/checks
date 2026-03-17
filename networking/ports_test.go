package networking

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

type mockProbeExecutor struct {
	responses map[string]string
	errors    map[string]error
}

func (m *mockProbeExecutor) ExecCommand(ctx context.Context, pod *corev1.Pod, command string) (stdout, stderr string, err error) {
	if err, ok := m.errors[command]; ok {
		return "", "", err
	}
	if resp, ok := m.responses[command]; ok {
		return resp, "", nil
	}
	return "", "", nil
}

func TestCheckUndeclaredContainerPorts(t *testing.T) {
	tests := []struct {
		name           string
		resources      *checks.DiscoveredResources
		expectedStatus string
		expectedReason string
	}{
		{
			name: "skip when no probe pods",
			resources: &checks.DiscoveredResources{
				Pods:          []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "test-pod"}}},
				ProbeExecutor: nil,
			},
			expectedStatus: "Skipped",
			expectedReason: "Probe pods not available",
		},
		{
			name: "skip when no pods",
			resources: &checks.DiscoveredResources{
				Pods:          []corev1.Pod{},
				ProbePods:     map[string]*corev1.Pod{"node1": {ObjectMeta: metav1.ObjectMeta{Name: "probe-pod"}}},
				ProbeExecutor: &mockProbeExecutor{},
			},
			expectedStatus: "Skipped",
			expectedReason: "No pods found",
		},
		{
			name: "compliant when all ports are declared",
			resources: &checks.DiscoveredResources{
				Pods: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
						Spec: corev1.PodSpec{
							NodeName: "node1",
							Containers: []corev1.Container{
								{
									Name: "app",
									Ports: []corev1.ContainerPort{
										{ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
										{ContainerPort: 9090, Protocol: corev1.ProtocolTCP},
									},
								},
							},
						},
					},
				},
				ProbePods: map[string]*corev1.Pod{
					"node1": {ObjectMeta: metav1.ObjectMeta{Name: "probe-pod"}},
				},
				ProbeExecutor: &mockProbeExecutor{
					responses: map[string]string{
						"crictl ps --name app -q 2>/dev/null | head -1":                         "abc123\n",
						"crictl inspect abc123 2>/dev/null | jq -r '.info.pid' 2>/dev/null":    "12345\n",
						"nsenter --target 12345 --mount --pid -- ss -tulwnH": "TCP   LISTEN 0      128       0.0.0.0:8080      0.0.0.0:*\nTCP   LISTEN 0      128       0.0.0.0:9090      0.0.0.0:*\n",
					},
				},
			},
			expectedStatus: "Compliant",
		},
		{
			name: "non-compliant when undeclared port is found",
			resources: &checks.DiscoveredResources{
				Pods: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
						Spec: corev1.PodSpec{
							NodeName: "node1",
							Containers: []corev1.Container{
								{
									Name: "app",
									Ports: []corev1.ContainerPort{
										{ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
									},
								},
							},
						},
					},
				},
				ProbePods: map[string]*corev1.Pod{
					"node1": {ObjectMeta: metav1.ObjectMeta{Name: "probe-pod"}},
				},
				ProbeExecutor: &mockProbeExecutor{
					responses: map[string]string{
						"crictl ps --name app -q 2>/dev/null | head -1":                         "abc123\n",
						"crictl inspect abc123 2>/dev/null | jq -r '.info.pid' 2>/dev/null":    "12345\n",
						"nsenter --target 12345 --mount --pid -- ss -tulwnH": "TCP   LISTEN 0      128       0.0.0.0:8080      0.0.0.0:*\nTCP   LISTEN 0      128       0.0.0.0:9999      0.0.0.0:*\n",
					},
				},
			},
			expectedStatus: "NonCompliant",
			expectedReason: "1 pod(s) have undeclared listening ports",
		},
		{
			name: "ignores istio reserved ports when istio-proxy present",
			resources: &checks.DiscoveredResources{
				Pods: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
						Spec: corev1.PodSpec{
							NodeName: "node1",
							Containers: []corev1.Container{
								{Name: "app"},
								{Name: "istio-proxy"}, // Istio sidecar present
							},
						},
					},
				},
				ProbePods: map[string]*corev1.Pod{
					"node1": {ObjectMeta: metav1.ObjectMeta{Name: "probe-pod"}},
				},
				ProbeExecutor: &mockProbeExecutor{
					responses: map[string]string{
						"crictl ps --name app -q 2>/dev/null | head -1":                      "abc123\n",
						"crictl inspect abc123 2>/dev/null | jq -r '.info.pid' 2>/dev/null": "12345\n",
						"nsenter --target 12345 --mount --pid -- ss -tulwnH":                 "TCP   LISTEN 0      128       0.0.0.0:15090     0.0.0.0:*\n", // Istio port
					},
				},
			},
			expectedStatus: "Compliant", // Should be compliant because Istio port is ignored
		},
		{
			name: "compliant when no ports are listening",
			resources: &checks.DiscoveredResources{
				Pods: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
						Spec: corev1.PodSpec{
							NodeName: "node1",
							Containers: []corev1.Container{
								{Name: "app"},
							},
						},
					},
				},
				ProbePods: map[string]*corev1.Pod{
					"node1": {ObjectMeta: metav1.ObjectMeta{Name: "probe-pod"}},
				},
				ProbeExecutor: &mockProbeExecutor{
					responses: map[string]string{
						"crictl ps --name app -q 2>/dev/null | head -1":                      "abc123\n",
						"crictl inspect abc123 2>/dev/null | jq -r '.info.pid' 2>/dev/null": "12345\n",
						"nsenter --target 12345 --mount --pid -- ss -tulwnH":                 "", // No listening ports
					},
				},
			},
			expectedStatus: "Compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckUndeclaredContainerPorts(tt.resources)
			if result.ComplianceStatus != tt.expectedStatus {
				t.Errorf("expected status %s, got %s", tt.expectedStatus, result.ComplianceStatus)
			}
			if tt.expectedReason != "" && result.Reason != tt.expectedReason {
				t.Errorf("expected reason %q, got %q", tt.expectedReason, result.Reason)
			}
		})
	}
}

func TestParseListeningPorts(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[portInfo]bool
	}{
		{
			name:  "parse TCP and UDP ports",
			input: "TCP   LISTEN 0      128       0.0.0.0:8080      0.0.0.0:*\nUDP   UNCONN 0      0         0.0.0.0:53        0.0.0.0:*\n",
			expected: map[portInfo]bool{
				{PortNumber: 8080, Protocol: "TCP"}: true,
			},
		},
		{
			name:  "parse IPv6 addresses",
			input: "TCP   LISTEN 0      128          [::]:9090         [::]:*\n",
			expected: map[portInfo]bool{
				{PortNumber: 9090, Protocol: "TCP"}: true,
			},
		},
		{
			name:     "empty input",
			input:    "",
			expected: map[portInfo]bool{},
		},
		{
			name:  "ignore non-LISTEN states",
			input: "TCP   ESTABLISHED 0      0       192.168.1.1:8080  192.168.1.2:12345\n",
			expected: map[portInfo]bool{},
		},
		{
			name:  "multiple listening ports",
			input: "TCP   LISTEN 0      128       0.0.0.0:80        0.0.0.0:*\nTCP   LISTEN 0      128       0.0.0.0:443       0.0.0.0:*\n",
			expected: map[portInfo]bool{
				{PortNumber: 80, Protocol: "TCP"}:  true,
				{PortNumber: 443, Protocol: "TCP"}: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseListeningPorts(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d ports, got %d", len(tt.expected), len(result))
			}
			for port := range tt.expected {
				if !result[port] {
					t.Errorf("expected port %+v to be in result", port)
				}
			}
		})
	}
}

func TestContainsIstioProxy(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected bool
	}{
		{
			name: "pod with istio-proxy",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app"},
						{Name: "istio-proxy"},
					},
				},
			},
			expected: true,
		},
		{
			name: "pod without istio-proxy",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app"},
						{Name: "sidecar"},
					},
				},
			},
			expected: false,
		},
		{
			name: "empty pod",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsIstioProxy(tt.pod)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
