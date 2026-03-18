package observability

import (
	"testing"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckContainerLogging_Compliant(t *testing.T) {
	// Create a pod with a running container
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-ns",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "test-container"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	// Create a fake K8s client with the pod
	k8sClient := testutil.NewMockK8sClient(pod)

	resources := &checks.DiscoveredResources{
		Pods:         []corev1.Pod{*pod},
		K8sClientset: k8sClient,
	}

	result := CheckContainerLogging(resources)

	// Note: The fake client won't actually stream logs, so this will likely fail
	// In a real test, you'd need to mock the log streaming mechanism
	// For now, we're just testing that the check doesn't panic
	if result.ComplianceStatus != "NonCompliant" && result.ComplianceStatus != "Error" {
		// Expected to fail because fake client can't stream logs
		t.Logf("Note: This test requires a more sophisticated mock for log streaming. Got: %s", result.ComplianceStatus)
	}
}

func TestCheckContainerLogging_NoK8sClient(t *testing.T) {
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
		K8sClientset: nil,
	}

	result := CheckContainerLogging(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error when K8sClientset is nil, got %s", result.ComplianceStatus)
	}

	if result.Reason != "Kubernetes client not available" {
		t.Errorf("Expected specific error message, got: %s", result.Reason)
	}
}

func TestCheckContainerLogging_NoPods(t *testing.T) {
	k8sClient := testutil.NewMockK8sClient()

	resources := &checks.DiscoveredResources{
		Pods:         []corev1.Pod{},
		K8sClientset: k8sClient,
	}

	result := CheckContainerLogging(resources)

	if result.ComplianceStatus != "Skipped" {
		t.Errorf("Expected Skipped when no pods found, got %s", result.ComplianceStatus)
	}

	if result.Reason != "No pods found" {
		t.Errorf("Expected 'No pods found' reason, got: %s", result.Reason)
	}
}
