package platform

import (
	"testing"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckIsRedHatRelease_Compliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		redhatReleaseCommand: {
			Stdout: "Red Hat Enterprise Linux release 8.5 (Ootpa)\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckIsRedHatRelease(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}

	if len(result.Details) != 1 {
		t.Errorf("Expected 1 detail, got %d", len(result.Details))
	}

	if !result.Details[0].Compliant {
		t.Errorf("Expected container to be compliant")
	}
}

func TestCheckIsRedHatRelease_NonCompliant_Ubuntu(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		redhatReleaseCommand: {
			Stdout: "Ubuntu 20.04.3 LTS\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckIsRedHatRelease(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant, got %s", result.ComplianceStatus)
	}

	if len(result.Details) != 1 {
		t.Errorf("Expected 1 detail, got %d", len(result.Details))
	}

	if result.Details[0].Compliant {
		t.Errorf("Expected container to be non-compliant")
	}
}

func TestCheckIsRedHatRelease_NonCompliant_UnknownBaseImage(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		redhatReleaseCommand: {
			Stdout: "Unknown Base Image\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckIsRedHatRelease(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant for Unknown Base Image, got %s", result.ComplianceStatus)
	}
}

func TestCheckIsRedHatRelease_Compliant_ServerRelease(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		redhatReleaseCommand: {
			Stdout: "Red Hat Enterprise Linux Server release 7.9 (Maipo)\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckIsRedHatRelease(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant for RHEL Server release, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckIsRedHatRelease_NonCompliant_JustRedHat(t *testing.T) {
	// A simple "Red Hat" string without the full version format should fail
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		redhatReleaseCommand: {
			Stdout: "Red Hat something custom\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckIsRedHatRelease(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant for non-standard Red Hat string, got %s", result.ComplianceStatus)
	}
}

func TestCheckIsRedHatRelease_NoProbeExecutor(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
		ProbeExecutor: nil,
	}

	result := CheckIsRedHatRelease(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error when ProbeExecutor is nil, got %s", result.ComplianceStatus)
	}
}

func TestCheckHyperthreadEnable_Compliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"lscpu | grep 'Thread(s) per core' | awk '{print $NF}'": {
			Stdout: "2\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Nodes: []corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-1",
					Labels: map[string]string{
						// No cloud provider labels = bare metal
					},
				},
			},
		},
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					NodeName: "worker-1",
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckHyperthreadEnable(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckHyperthreadEnable_NonCompliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"lscpu | grep 'Thread(s) per core' | awk '{print $NF}'": {
			Stdout: "1\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Nodes: []corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-1",
					Labels: map[string]string{
						// No cloud provider labels = bare metal
					},
				},
			},
		},
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					NodeName: "worker-1",
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckHyperthreadEnable(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHyperthreadEnable_CloudNode_Skipped(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Nodes: []corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-1",
					Labels: map[string]string{
						"node.kubernetes.io/instance-type": "m5.large", // Cloud node
					},
				},
			},
		},
		ProbeExecutor: testutil.NewMockProbeExecutor(nil),
	}

	result := CheckHyperthreadEnable(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped for cloud node, got %s", result.ComplianceStatus)
	}
}
