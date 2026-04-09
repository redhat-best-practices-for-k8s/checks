package observability

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
)

func TestCheckCRDStatus_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "tests.example.com"},
				Spec: apiextv1.CustomResourceDefinitionSpec{
					Versions: []apiextv1.CustomResourceDefinitionVersion{
						{
							Name: "v1",
							Subresources: &apiextv1.CustomResourceSubresources{
								Status: &apiextv1.CustomResourceSubresourceStatus{},
							},
						},
					},
				},
			},
		},
	}
	result := CheckCRDStatus(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckCRDStatus_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "tests.example.com"},
				Spec: apiextv1.CustomResourceDefinitionSpec{
					Versions: []apiextv1.CustomResourceDefinitionVersion{
						{Name: "v1"},
					},
				},
			},
		},
	}
	result := CheckCRDStatus(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckTerminationPolicy_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError},
					},
				},
			},
		},
	}
	result := CheckTerminationPolicy(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckTerminationPolicy_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1"},
					},
				},
			},
		},
	}
	result := CheckTerminationPolicy(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckTerminationPolicy_NoPods(t *testing.T) {
	result := CheckTerminationPolicy(&checks.DiscoveredResources{})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- PodDisruptionBudget checks ---

func TestCheckPodDisruptionBudget_Deployment_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Replicas: testutil.Int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			},
		}},
		PodDisruptionBudgets: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "pdb1", Namespace: "ns1"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: intOrStringPtr(1),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckPodDisruptionBudget_Deployment_NoPDB_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Replicas: testutil.Int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodDisruptionBudget_StatefulSet_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "sts1", Namespace: "ns1"},
			Spec: appsv1.StatefulSetSpec{
				Replicas: testutil.Int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "db"}},
				},
			},
		}},
		PodDisruptionBudgets: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "pdb1", Namespace: "ns1"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: intOrStringPtr(1),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "db"},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckPodDisruptionBudget_StatefulSet_NoPDB_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "sts1", Namespace: "ns1"},
			Spec: appsv1.StatefulSetSpec{
				Replicas: testutil.Int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "db"}},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodDisruptionBudget_InvalidMinAvailableZero_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Replicas: testutil.Int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			},
		}},
		PodDisruptionBudgets: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "pdb1", Namespace: "ns1"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MinAvailable: intOrStringPtr(0),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for minAvailable=0, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodDisruptionBudget_InvalidMaxUnavailableGEReplicas_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Replicas: testutil.Int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			},
		}},
		PodDisruptionBudgets: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "pdb1", Namespace: "ns1"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: intOrStringPtr(3),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for maxUnavailable >= replicas, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodDisruptionBudget_ZoneAware_NonCompliant(t *testing.T) {
	// 2 zones, 4 replicas => maxReplicasPerZone = ceil(4/2) = 2
	// maxUnavailable=1 < 2 => not zone-aware
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Replicas: testutil.Int32Ptr(4),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			},
		}},
		PodDisruptionBudgets: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "pdb1", Namespace: "ns1"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: intOrStringPtr(1),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		}},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: map[string]string{"topology.kubernetes.io/zone": "zone-a"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "node2", Labels: map[string]string{"topology.kubernetes.io/zone": "zone-b"}}},
		},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for non-zone-aware PDB, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodDisruptionBudget_ZoneAware_Compliant(t *testing.T) {
	// 2 zones, 4 replicas => maxReplicasPerZone = ceil(4/2) = 2
	// maxUnavailable=2 >= 2 => zone-aware
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Replicas: testutil.Int32Ptr(4),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			},
		}},
		PodDisruptionBudgets: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "pdb1", Namespace: "ns1"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: intOrStringPtr(2),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		}},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: map[string]string{"topology.kubernetes.io/zone": "zone-a"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "node2", Labels: map[string]string{"topology.kubernetes.io/zone": "zone-b"}}},
		},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for zone-aware PDB, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckPodDisruptionBudget_MatchExpressions_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Replicas: testutil.Int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web", "tier": "frontend"}},
				},
			},
		}},
		PodDisruptionBudgets: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "pdb1", Namespace: "ns1"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: intOrStringPtr(1),
				Selector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"web", "api"},
					}},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant with matchExpressions, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckPodDisruptionBudget_DifferentNamespace_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Replicas: testutil.Int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			},
		}},
		PodDisruptionBudgets: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "pdb1", Namespace: "ns2"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: intOrStringPtr(1),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (PDB in different namespace), got %s", result.ComplianceStatus)
	}
}

func TestCheckPodDisruptionBudget_NoWorkloads(t *testing.T) {
	result := CheckPodDisruptionBudget(&checks.DiscoveredResources{})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func intOrStringPtr(val int) *intstr.IntOrString {
	v := intstr.FromInt32(int32(val))
	return &v
}
