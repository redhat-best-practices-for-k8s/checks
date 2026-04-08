package performance

import (
	"testing"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckSharedCPUPoolSchedulingPolicy_Compliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"pgrep -P 1 | head -1": {
			Stdout: "1234\n",
			Stderr: "",
			Err:    nil,
		},
		"ps -e -o pid --no-headers": {
			Stdout: "1234\n5678\n",
			Stderr: "",
			Err:    nil,
		},
		"chrt -p 1234": {
			Stdout: "pid 1234's current scheduling policy: SCHED_OTHER\n",
			Stderr: "",
			Err:    nil,
		},
		"chrt -p 5678": {
			Stdout: "pid 5678's current scheduling policy: SCHED_OTHER\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					HostPID: false,
					Containers: []corev1.Container{
						{
							Name: "container1",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU: resource.MustParse("100m"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU: resource.MustParse("200m"), // Not equal = non-guaranteed
								},
							},
						},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckSharedCPUPoolSchedulingPolicy(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckExclusiveCPUPoolSchedulingPolicy_Compliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"pgrep -P 1 | head -1": {
			Stdout: "1234\n",
			Stderr: "",
			Err:    nil,
		},
		"ps -e -o pid --no-headers": {
			Stdout: "1234\n",
			Stderr: "",
			Err:    nil,
		},
		"chrt -p 1234": {
			Stdout: "pid 1234's current scheduling policy: SCHED_FIFO\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					HostPID: false,
					Containers: []corev1.Container{
						{
							Name: "container1",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("2"),
									corev1.ResourceMemory: resource.MustParse("2Gi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("2"), // Equal = guaranteed
									corev1.ResourceMemory: resource.MustParse("2Gi"),
								},
							},
						},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckExclusiveCPUPoolSchedulingPolicy(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckExclusiveCPUPoolSchedulingPolicy_NonCompliant(t *testing.T) {
	mockProbe := testutil.NewMockProbeExecutor(map[string]testutil.MockProbeResponse{
		"pgrep -P 1 | head -1": {
			Stdout: "1234\n",
			Stderr: "",
			Err:    nil,
		},
		"ps -e -o pid --no-headers": {
			Stdout: "1234\n",
			Stderr: "",
			Err:    nil,
		},
		"chrt -p 1234": {
			Stdout: "pid 1234's current scheduling policy: SCHED_OTHER\n",
			Stderr: "",
			Err:    nil,
		},
	})

	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					HostPID: false,
					Containers: []corev1.Container{
						{
							Name: "container1",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("2"),
									corev1.ResourceMemory: resource.MustParse("2Gi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("2"),
									corev1.ResourceMemory: resource.MustParse("2Gi"),
								},
							},
						},
					},
				},
			},
		},
		ProbeExecutor: mockProbe,
	}

	result := CheckExclusiveCPUPoolSchedulingPolicy(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSharedCPUPoolSchedulingPolicy_NoPods(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods:          []corev1.Pod{},
		ProbeExecutor: testutil.NewMockProbeExecutor(nil),
	}

	result := CheckSharedCPUPoolSchedulingPolicy(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped when no pods, got %s", result.ComplianceStatus)
	}
}

func TestCheckSharedCPUPoolSchedulingPolicy_HostPID_Skipped(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "test-ns"},
				Spec: corev1.PodSpec{
					HostPID: true, // Should be skipped
					Containers: []corev1.Container{
						{Name: "container1"},
					},
				},
			},
		},
		ProbeExecutor: testutil.NewMockProbeExecutor(nil),
	}

	result := CheckSharedCPUPoolSchedulingPolicy(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped when all pods have HostPID, got %s", result.ComplianceStatus)
	}
}

func TestIsGuaranteedPod_Guaranteed(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("1"),
							corev1.ResourceMemory: resource.MustParse("1Gi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("1"),
							corev1.ResourceMemory: resource.MustParse("1Gi"),
						},
					},
				},
			},
		},
	}

	if !isGuaranteedPod(pod) {
		t.Error("Expected pod to be guaranteed QoS")
	}
}

func TestIsGuaranteedPod_NotGuaranteed(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU: resource.MustParse("100m"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU: resource.MustParse("200m"), // Not equal
						},
					},
				},
			},
		},
	}

	if isGuaranteedPod(pod) {
		t.Error("Expected pod to NOT be guaranteed QoS")
	}
}

func TestIsExpectedPolicy_SharedPool(t *testing.T) {
	tests := []struct {
		actual   string
		expected bool
	}{
		{schedOther, true},
		{schedBatch, true},
		{schedIdle, true},
		{schedFIFO, false},
		{schedRR, false},
	}

	for _, tt := range tests {
		result := isExpectedPolicy(tt.actual, schedOther, "shared")
		if result != tt.expected {
			t.Errorf("isExpectedPolicy(%q, %q, shared) = %v, expected %v",
				tt.actual, schedOther, result, tt.expected)
		}
	}
}

func TestIsExpectedPolicy_ExclusivePool(t *testing.T) {
	tests := []struct {
		actual   string
		expected bool
	}{
		{schedFIFO, true},
		{schedRR, true},
		{schedOther, false},
		{schedBatch, false},
	}

	for _, tt := range tests {
		result := isExpectedPolicy(tt.actual, schedFIFO, "exclusive")
		if result != tt.expected {
			t.Errorf("isExpectedPolicy(%q, %q, exclusive) = %v, expected %v",
				tt.actual, schedFIFO, result, tt.expected)
		}
	}
}
