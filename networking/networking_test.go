package networking

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// --- Dual-stack service ---

func TestCheckDualStackService_Compliant(t *testing.T) {
	policy := corev1.IPFamilyPolicyPreferDualStack
	resources := &checks.DiscoveredResources{
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
			Spec: corev1.ServiceSpec{
				IPFamilyPolicy: &policy,
			},
		}},
	}
	result := CheckDualStackService(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckDualStackService_NonCompliant(t *testing.T) {
	policy := corev1.IPFamilyPolicySingleStack
	resources := &checks.DiscoveredResources{
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
			Spec: corev1.ServiceSpec{
				IPFamilyPolicy: &policy,
			},
		}},
	}
	result := CheckDualStackService(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckDualStackService_Headless_Skipped(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
			Spec: corev1.ServiceSpec{
				ClusterIP: "None",
			},
		}},
	}
	result := CheckDualStackService(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (headless skipped), got %s", result.ComplianceStatus)
	}
}

// --- NetworkPolicy deny-all ---

func TestCheckNetworkPolicyDenyAll_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
		}},
		NetworkPolicies: []networkingv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "ns1"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
			},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckNetworkPolicyDenyAll(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNetworkPolicyDenyAll_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
		}},
		NetworkPolicies: []networkingv1.NetworkPolicy{},
		Namespaces:      []string{"ns1"},
	}
	result := CheckNetworkPolicyDenyAll(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- NetworkPolicy deny-all additional scenarios (from certsuite policies_test.go) ---

func TestCheckNetworkPolicyDenyAll_NonEmptySelector(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
		}},
		NetworkPolicies: []networkingv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "ns1"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "nginx"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
			},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckNetworkPolicyDenyAll(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for non-empty selector (not a deny-all), got %s", result.ComplianceStatus)
	}
}

func TestCheckNetworkPolicyDenyAll_IngressOnly(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
		}},
		NetworkPolicies: []networkingv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-ingress", Namespace: "ns1"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
				},
			},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckNetworkPolicyDenyAll(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (missing egress deny-all), got %s", result.ComplianceStatus)
	}
}

func TestCheckNetworkPolicyDenyAll_WithEgressRules(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
		}},
		NetworkPolicies: []networkingv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-egress", Namespace: "ns1"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{{}},
			},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckNetworkPolicyDenyAll(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (egress rules present, not a deny-all), got %s", result.ComplianceStatus)
	}
}

// --- Reserved ports ---

func TestCheckReservedPartnerPorts_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "c1",
					Ports: []corev1.ContainerPort{{ContainerPort: 22222}},
				}},
			},
		}},
	}
	result := CheckReservedPartnerPorts(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckReservedPartnerPorts_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "c1",
					Ports: []corev1.ContainerPort{{ContainerPort: 8080}},
				}},
			},
		}},
	}
	result := CheckReservedPartnerPorts(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckOCPReservedPorts_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "c1",
					Ports: []corev1.ContainerPort{{ContainerPort: 22623}},
				}},
			},
		}},
	}
	result := CheckOCPReservedPorts(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- SR-IOV restart label ---

func TestCheckSRIOVRestartLabel_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				Labels:      map[string]string{"restart-on-reboot": "true"},
				Annotations: map[string]string{"k8s.v1.cni.cncf.io/networks": "sriov-net"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceName("openshift.io/sriov"): resource.MustParse("1"),
						},
					},
				}},
			},
		}},
	}
	result := CheckSRIOVRestartLabel(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSRIOVRestartLabel_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				Annotations: map[string]string{"k8s.v1.cni.cncf.io/networks": "sriov-net"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceName("openshift.io/sriov"): resource.MustParse("1"),
						},
					},
				}},
			},
		}},
	}
	result := CheckSRIOVRestartLabel(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSRIOVRestartLabel_NoSRIOV_Skipped(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckSRIOVRestartLabel(resources)
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}
