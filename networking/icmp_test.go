package networking

import (
	"testing"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckICMPv4Connectivity_Compliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"ping -4 -c 5 10.0.0.2": {
			Stdout: "5 packets transmitted, 5 received, 0% packet loss\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "test-ns"},
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "10.0.0.2"}},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckICMPv4Connectivity(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}

	if len(result.Details) == 0 {
		t.Error("Expected details for ICMP tests")
	}
}

func TestCheckICMPv4Connectivity_NonCompliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"ping -4 -c 5 10.0.0.2": {
			Stdout: "5 packets transmitted, 0 received, 100% packet loss\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "test-ns"},
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "10.0.0.2"}},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckICMPv4Connectivity(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckICMPv6Connectivity_Compliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"ping -6 -c 5 2001:db8::2": {
			Stdout: "5 packets transmitted, 5 received, 0% packet loss\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "2001:db8::1"}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "test-ns"},
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "2001:db8::2"}},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckICMPv6Connectivity(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckICMPv4Connectivity_NotEnoughPods(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}},
				},
			},
		},
		ProbeExecutor: testutil.NewMockProbeExecutor(nil),
	}

	result := CheckICMPv4Connectivity(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped with 1 pod, got %s", result.ComplianceStatus)
	}

	if result.Reason != "At least 2 pods required for ICMP connectivity testing" {
		t.Errorf("Expected specific skip reason, got: %s", result.Reason)
	}
}

func TestCheckICMPv4Connectivity_NoProbeExecutor(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "test-ns"}},
		},
		ProbeExecutor: nil,
	}

	result := CheckICMPv4Connectivity(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error when ProbeExecutor is nil, got %s", result.ComplianceStatus)
	}
}

func TestCheckICMPv4Connectivity_NoIPv4Addresses(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "2001:db8::1"}}, // Only IPv6
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "test-ns"},
				Status: corev1.PodStatus{
					PodIPs: []corev1.PodIP{{IP: "2001:db8::2"}}, // Only IPv6
				},
			},
		},
		ProbeExecutor: testutil.NewMockProbeExecutor(nil),
	}

	result := CheckICMPv4Connectivity(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped when no IPv4 addresses, got %s", result.ComplianceStatus)
	}
}

func TestParsePingOutput_Success(t *testing.T) {
	output := "5 packets transmitted, 5 received, 0% packet loss"
	result := parsePingOutput(output)

	if !result.success {
		t.Errorf("Expected success=true, got false")
	}

	if result.transmitted != 5 {
		t.Errorf("Expected transmitted=5, got %d", result.transmitted)
	}

	if result.received != 5 {
		t.Errorf("Expected received=5, got %d", result.received)
	}
}

func TestParsePingOutput_PartialLoss(t *testing.T) {
	output := "5 packets transmitted, 4 received, 20% packet loss"
	result := parsePingOutput(output)

	if !result.success {
		t.Errorf("Expected success=true with acceptable loss, got false")
	}

	if result.transmitted != 5 {
		t.Errorf("Expected transmitted=5, got %d", result.transmitted)
	}

	if result.received != 4 {
		t.Errorf("Expected received=4, got %d", result.received)
	}
}

func TestParsePingOutput_HighLoss(t *testing.T) {
	output := "5 packets transmitted, 2 received, 60% packet loss"
	result := parsePingOutput(output)

	if result.success {
		t.Errorf("Expected success=false with high loss, got true")
	}
}

func TestParsePingOutput_WithErrors(t *testing.T) {
	output := "5 packets transmitted, 3 received, +2 errors, 40% packet loss"
	result := parsePingOutput(output)

	if result.success {
		t.Errorf("Expected success=false when errors present, got true")
	}

	if result.errors != 2 {
		t.Errorf("Expected errors=2, got %d", result.errors)
	}
}

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"2001:db8::1", false},
		{"::1", false},
		{"fe80::1", false},
	}

	for _, tt := range tests {
		result := isIPv4(tt.ip)
		if result != tt.expected {
			t.Errorf("isIPv4(%q) = %v, expected %v", tt.ip, result, tt.expected)
		}
	}
}
