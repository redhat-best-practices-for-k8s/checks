package observability

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- PodDisruptionBudget checks ---

func TestCheckPodDisruptionBudget_Compliant(t *testing.T) {
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
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
			},
		}},
	}
	result := CheckPodDisruptionBudget(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodDisruptionBudget_NonCompliant(t *testing.T) {
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

func TestCheckPodDisruptionBudget_Skipped(t *testing.T) {
	result := CheckPodDisruptionBudget(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}
