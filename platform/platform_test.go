package platform

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// --- Hugepages 2Mi only ---

func TestCheckHugepages2MiOnly_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceName("hugepages-2Mi"): resource.MustParse("256Mi"),
						},
					},
				}},
			},
		}},
	}
	result := CheckHugepages2MiOnly(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for 2Mi hugepages, got %s", result.ComplianceStatus)
	}
}

func TestCheckHugepages2MiOnly_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceName("hugepages-1Gi"): resource.MustParse("1Gi"),
						},
					},
				}},
			},
		}},
	}
	result := CheckHugepages2MiOnly(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for 1Gi hugepages, got %s", result.ComplianceStatus)
	}
}

func TestCheckHugepages2MiOnly_NoPods_Skipped(t *testing.T) {
	result := CheckHugepages2MiOnly(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- Node count ---

func TestCheckNodeCount_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-3"}},
		},
	}
	result := CheckNodeCount(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for 3 workers, got %s", result.ComplianceStatus)
	}
}

func TestCheckNodeCount_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-2"}},
		},
	}
	result := CheckNodeCount(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for 2 workers, got %s", result.ComplianceStatus)
	}
}

func TestCheckNodeCount_MasterOnly(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{
				Name:   "master-1",
				Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
			}},
			{ObjectMeta: metav1.ObjectMeta{
				Name:   "master-2",
				Labels: map[string]string{"node-role.kubernetes.io/master": ""},
			}},
		},
	}
	result := CheckNodeCount(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for 0 workers, got %s", result.ComplianceStatus)
	}
}

// --- Service mesh usage ---

func TestCheckServiceMeshUsage_IstioAnnotation_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				Annotations: map[string]string{"sidecar.istio.io/inject": "true"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckServiceMeshUsage(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for Istio sidecar annotation, got %s", result.ComplianceStatus)
	}
}

func TestCheckServiceMeshUsage_NoSidecar_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckServiceMeshUsage(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}
