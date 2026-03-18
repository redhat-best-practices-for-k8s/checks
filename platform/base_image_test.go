package platform

import (
	"strings"
	"testing"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckUnalteredBaseImage_Compliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"crictl exec containerd://test-container-id sh -c 'rpm -qa'": {
			Stdout: "bash-4.4.19-1.el8.x86_64\ncoreutils-8.30-1.el8.x86_64\n", // Small package list
			Stderr: "",
			Err:    nil,
		},
		// Mock the artifact check (batched command)
		"crictl exec containerd://test-container-id sh -c 'for p in /var/cache/dnf /var/cache/yum /tmp/yum-* /var/lib/rpm/__db.*; do [ -e \"$p\" ] && echo \"$p\"; done'": {
			Stdout: "", // No artifacts found
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
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:        "test-container",
							ContainerID: "containerd://test-container-id",
						},
					},
				},
			},
		},
		OpenshiftVersion: "4.12.0",
		ProbeExecutor:    mockProbe,
	}

	result := CheckUnalteredBaseImage(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckUnalteredBaseImage_NonCompliant_TooManyPackages(t *testing.T) {
	// Create a package list with >500 packages to trigger the modified detection
	var packages strings.Builder
	for i := range 600 {
		packages.WriteString("package-" + string(rune(i)) + "-1.0.0\n")
	}

	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"crictl exec containerd://test-container-id sh -c 'rpm -qa'": {
			Stdout: packages.String(),
			Stderr: "",
			Err:    nil,
		},
		// Mock the artifact check (batched command)
		"crictl exec containerd://test-container-id sh -c 'for p in /var/cache/dnf /var/cache/yum /tmp/yum-* /var/lib/rpm/__db.*; do [ -e \"$p\" ] && echo \"$p\"; done'": {
			Stdout: "", // No artifacts
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
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:        "test-container",
							ContainerID: "containerd://test-container-id",
						},
					},
				},
			},
		},
		OpenshiftVersion: "4.12.0",
		ProbeExecutor:    mockProbe,
	}

	result := CheckUnalteredBaseImage(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant with many packages, got %s", result.ComplianceStatus)
	}
}

func TestCheckUnalteredBaseImage_NonCompliant_PackageManagerArtifacts(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"crictl exec containerd://test-container-id sh -c 'rpm -qa'": {
			Stdout: "bash-4.4.19-1.el8.x86_64\n",
			Stderr: "",
			Err:    nil,
		},
		"crictl exec containerd://test-container-id sh -c 'for p in /var/cache/dnf /var/cache/yum /tmp/yum-* /var/lib/rpm/__db.*; do [ -e \"$p\" ] && echo \"$p\"; done'": {
			Stdout: "/var/cache/dnf\n", // Artifacts found
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
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:        "test-container",
							ContainerID: "containerd://test-container-id",
						},
					},
				},
			},
		},
		OpenshiftVersion: "4.12.0",
		ProbeExecutor:    mockProbe,
	}

	result := CheckUnalteredBaseImage(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant with package manager artifacts, got %s", result.ComplianceStatus)
	}
}

func TestCheckUnalteredBaseImage_NotOCP_Skipped(t *testing.T) {
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
		OpenshiftVersion: "", // Not OCP
		ProbeExecutor:    testutil.NewMockProbeExecutor(nil),
	}

	result := CheckUnalteredBaseImage(resources)

	if result.ComplianceStatus != "Skipped" {
		t.Errorf("Expected Skipped on non-OCP cluster, got %s", result.ComplianceStatus)
	}
}

func TestCheckUnalteredBaseImage_NoProbeExecutor(t *testing.T) {
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
		OpenshiftVersion: "4.12.0",
		ProbeExecutor:    nil,
	}

	result := CheckUnalteredBaseImage(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error when ProbeExecutor is nil, got %s", result.ComplianceStatus)
	}
}

func TestCheckUnalteredBaseImage_NoContainerID(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(nil)

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:        "test-container",
							ContainerID: "", // Empty container ID
						},
					},
				},
			},
		},
		OpenshiftVersion: "4.12.0",
		ProbeExecutor:    mockProbe,
	}

	result := CheckUnalteredBaseImage(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant when container ID not found, got %s", result.ComplianceStatus)
	}

	if len(result.Details) == 0 {
		t.Error("Expected details explaining the failure")
	}
}
