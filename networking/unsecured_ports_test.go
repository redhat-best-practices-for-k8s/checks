package networking

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

func TestParseNonTLSPortsAnnotation(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		expected    map[int32]bool
	}{
		{name: "no annotation", annotations: nil, expected: map[int32]bool{}},
		{name: "empty annotation value", annotations: map[string]string{nonTLSPortsAnnotation: ""}, expected: map[int32]bool{}},
		{name: "single port", annotations: map[string]string{nonTLSPortsAnnotation: "8080"}, expected: map[int32]bool{8080: true}},
		{name: "multiple ports with whitespace", annotations: map[string]string{nonTLSPortsAnnotation: "80, 443, 8080"}, expected: map[int32]bool{80: true, 443: true, 8080: true}},
		{name: "invalid port skipped", annotations: map[string]string{nonTLSPortsAnnotation: "80, abc, 443"}, expected: map[int32]bool{80: true, 443: true}},
		{name: "out-of-range ports skipped", annotations: map[string]string{nonTLSPortsAnnotation: "0, 80, 70000"}, expected: map[int32]bool{80: true}},
		{name: "unrelated annotation ignored", annotations: map[string]string{"other-annotation": "8080"}, expected: map[int32]bool{}},
		{name: "min and max valid ports", annotations: map[string]string{nonTLSPortsAnnotation: "1, 65535"}, expected: map[int32]bool{1: true, 65535: true}},
		{name: "trailing comma", annotations: map[string]string{nonTLSPortsAnnotation: "80,"}, expected: map[int32]bool{80: true}},
		{name: "blank token skipped", annotations: map[string]string{nonTLSPortsAnnotation: "80, , 443"}, expected: map[int32]bool{80: true, 443: true}},
		{name: "duplicate ports", annotations: map[string]string{nonTLSPortsAnnotation: "80,80"}, expected: map[int32]bool{80: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tt.annotations}}
			got := parseNonTLSPortsAnnotation(pod)
			if len(got) != len(tt.expected) {
				t.Fatalf("got %v, want %v", got, tt.expected)
			}
			for port := range tt.expected {
				if !got[port] {
					t.Errorf("missing expected port %d in %v", port, got)
				}
			}
		})
	}
}

func listeningPod(name, node, ip string, annotations map[string]string, istio bool) corev1.Pod {
	containers := []corev1.Container{{Name: "app"}}
	if istio {
		containers = append(containers, corev1.Container{Name: "istio-proxy"})
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", Annotations: annotations},
		Spec:       corev1.PodSpec{NodeName: node, Containers: containers},
		Status: corev1.PodStatus{
			PodIP: ip,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "cri-o://abc123"},
			},
		},
	}
}

func TestCheckUnsecuredContainerPorts_NoProbePods(t *testing.T) {
	result := CheckUnsecuredContainerPorts(&checks.DiscoveredResources{
		Pods: []corev1.Pod{listeningPod("p", "n1", "10.0.0.2", nil, false)},
	})
	if result.ComplianceStatus != checks.StatusSkipped {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckUnsecuredContainerPorts_NoPods(t *testing.T) {
	result := CheckUnsecuredContainerPorts(&checks.DiscoveredResources{
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: newContainsMock(),
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
	if result.Reason != "No pods found" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestCheckUnsecuredContainerPorts_Plaintext(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "crictl inspect", stdout: "12345\n"},
		mockPattern{key: "ss -tulwnH", stdout: "TCP   LISTEN 0      128       0.0.0.0:8080      0.0.0.0:*\n"},
		mockPattern{key: "s_client", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.2\n---"},
	)
	result := CheckUnsecuredContainerPorts(&checks.DiscoveredResources{
		Pods:          []corev1.Pod{listeningPod("app", "n1", "10.0.0.2", nil, false)},
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
	})
	if result.ComplianceStatus != checks.StatusNonCompliant {
		t.Errorf("expected NonCompliant, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckUnsecuredContainerPorts_TLS(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "crictl inspect", stdout: "12345\n"},
		mockPattern{key: "ss -tulwnH", stdout: "TCP   LISTEN 0      128       0.0.0.0:443      0.0.0.0:*\n"},
		mockPattern{key: "s_client", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n---"},
	)
	result := CheckUnsecuredContainerPorts(&checks.DiscoveredResources{
		Pods:          []corev1.Pod{listeningPod("app", "n1", "10.0.0.2", nil, false)},
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckUnsecuredContainerPorts_ExemptAnnotation(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "crictl inspect", stdout: "12345\n"},
		mockPattern{key: "ss -tulwnH", stdout: "TCP   LISTEN 0      128       0.0.0.0:8080      0.0.0.0:*\n"},
	)
	result := CheckUnsecuredContainerPorts(&checks.DiscoveredResources{
		Pods: []corev1.Pod{listeningPod("app", "n1", "10.0.0.2", map[string]string{
			nonTLSPortsAnnotation: "8080",
		}, false)},
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant for exempt port, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
	found := false
	for _, d := range result.Details {
		if d.Compliant && d.Message == "Port 8080 exempt via annotation" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exemption detail, got %+v", result.Details)
	}
}

func TestCheckUnsecuredContainerPorts_IstioReservedSkipped(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "crictl inspect", stdout: "12345\n"},
		mockPattern{key: "ss -tulwnH", stdout: "TCP   LISTEN 0      128       0.0.0.0:15090      0.0.0.0:*\n"},
	)
	result := CheckUnsecuredContainerPorts(&checks.DiscoveredResources{
		Pods:          []corev1.Pod{listeningPod("app", "n1", "10.0.0.2", nil, true)},
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant (istio port ignored), got %s (%s)", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckUnsecuredContainerPorts_Unreachable(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "crictl inspect", stdout: "12345\n"},
		mockPattern{key: "ss -tulwnH", stdout: "TCP   LISTEN 0      128       0.0.0.0:8080      0.0.0.0:*\n"},
		mockPattern{key: "s_client", stdout: "connect:errno=111\nConnection refused"},
	)
	result := CheckUnsecuredContainerPorts(&checks.DiscoveredResources{
		Pods:          []corev1.Pod{listeningPod("app", "n1", "10.0.0.2", nil, false)},
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("unreachable should be compliant, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckUnsecuredContainerPorts_NoListeningPorts(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "crictl inspect", stdout: "12345\n"},
		mockPattern{key: "ss -tulwnH", stdout: ""},
	)
	result := CheckUnsecuredContainerPorts(&checks.DiscoveredResources{
		Pods:          []corev1.Pod{listeningPod("app", "n1", "10.0.0.2", nil, false)},
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
}
