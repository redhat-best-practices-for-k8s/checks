package networking

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

func TestCheckTLSMinimumVersion_NoProbePods(t *testing.T) {
	result := CheckTLSMinimumVersion(&checks.DiscoveredResources{
		Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "svc"}}},
	})
	if result.ComplianceStatus != checks.StatusSkipped {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckTLSMinimumVersion_NoServices(t *testing.T) {
	result := CheckTLSMinimumVersion(&checks.DiscoveredResources{
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: newContainsMock(),
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
	if result.Reason != "No services found" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestCheckTLSMinimumVersion_HeadlessServiceSkipped(t *testing.T) {
	result := CheckTLSMinimumVersion(&checks.DiscoveredResources{
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: newContainsMock(),
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "headless", Namespace: "ns"},
			Spec: corev1.ServiceSpec{
				ClusterIP: corev1.ClusterIPNone,
				Ports:     []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			},
		}},
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
	if len(result.Details) != 0 {
		t.Errorf("headless service should not be probed, got %d details", len(result.Details))
	}
}

func TestCheckTLSMinimumVersion_EmptyClusterIPSkipped(t *testing.T) {
	result := CheckTLSMinimumVersion(&checks.DiscoveredResources{
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: newContainsMock(),
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "no-ip", Namespace: "ns"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "",
				Ports:     []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			},
		}},
	})
	if len(result.Details) != 0 {
		t.Errorf("empty ClusterIP should not be probed, got %d details", len(result.Details))
	}
}

func TestCheckTLSMinimumVersion_NonTCPPortSkipped(t *testing.T) {
	result := CheckTLSMinimumVersion(&checks.DiscoveredResources{
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: newContainsMock(),
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "udp-svc", Namespace: "ns"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.0.0.1",
				Ports:     []corev1.ServicePort{{Port: 53, Protocol: corev1.ProtocolUDP}},
			},
		}},
	})
	if len(result.Details) != 0 {
		t.Errorf("UDP port should not be probed, got %d details", len(result.Details))
	}
}

func TestCheckTLSMinimumVersion_Unreachable(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "connect:errno=111\nConnection refused"},
	)
	result := CheckTLSMinimumVersion(&checks.DiscoveredResources{
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "ns"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.0.0.1",
				Ports:     []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			},
		}},
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("unreachable should be compliant, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
	if len(result.Details) != 1 || !result.Details[0].Compliant {
		t.Errorf("expected one compliant unreachable detail, got %+v", result.Details)
	}
}

func TestCheckTLSMinimumVersion_Compliant(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "-cipher", stdout: "CONNECTED(00000003)\n---\nssl handshake failure\n---"},
		mockPattern{key: "-tls1_3", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n---"},
		mockPattern{key: "-tls1_2", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.2\nCipher    : ECDHE-RSA-AES128-GCM-SHA256\n---"},
		mockPattern{key: "-tls1_1", stdout: "CONNECTED(00000003)\n---\nssl handshake failure\n---"},
	)
	result := CheckTLSMinimumVersion(&checks.DiscoveredResources{
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "ns"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.0.0.1",
				Ports:     []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			},
		}},
	})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckTLSMinimumVersion_NonCompliant(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "-tls1_2", stdout: "CONNECTED(00000003)\n---\nssl handshake failure\nalert protocol version\n---"},
		mockPattern{key: "s_client", stdout: "CONNECTED(00000003)\n---\nssl handshake failure\n---"},
	)
	result := CheckTLSMinimumVersion(&checks.DiscoveredResources{
		ProbePods:     map[string]*corev1.Pod{"n1": probePod()},
		ProbeExecutor: mock,
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "ns"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.0.0.1",
				Ports:     []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			},
		}},
	})
	if result.ComplianceStatus != checks.StatusNonCompliant {
		t.Errorf("expected NonCompliant, got %s (%s)", result.ComplianceStatus, result.Reason)
	}
}
