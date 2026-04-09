package accesscontrol

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
)

type mockProbeResponse struct {
	stdout, stderr string
	err            error
}

type mockProbeExecutor struct {
	responses map[string]mockProbeResponse
}

func (m *mockProbeExecutor) ExecCommand(_ context.Context, _ *corev1.Pod, command string) (string, string, error) {
	if r, ok := m.responses[command]; ok {
		return r.stdout, r.stderr, r.err
	}
	return "", "", fmt.Errorf("unexpected command: %s", command)
}

func makeProbePod(nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "probe-" + nodeName, Namespace: "debug"},
		Spec:       corev1.PodSpec{NodeName: nodeName},
	}
}

// --- Host checks ---

func TestCheckHostNetwork_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"}},
		},
	}
	result := CheckHostNetwork(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHostNetwork_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{HostNetwork: true},
			},
		},
	}
	result := CheckHostNetwork(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Errorf("expected 1 detail, got %d", len(result.Details))
	}
}

func TestCheckHostNetwork_NoPods(t *testing.T) {
	result := CheckHostNetwork(&checks.DiscoveredResources{})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckHostPath_NonCompliant(t *testing.T) {
	hostPathType := corev1.HostPathDirectory
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{{
						Name: "host-vol",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/data", Type: &hostPathType},
						},
					}},
				},
			},
		},
	}
	result := CheckHostPath(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHostPath_EmptyPath(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{{
						Name: "host-vol",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: ""},
						},
					}},
				},
			},
		},
	}
	result := CheckHostPath(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for empty path, got %s", result.ComplianceStatus)
	}
}

func TestCheckHostIPC_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{HostIPC: true},
			},
		},
	}
	result := CheckHostIPC(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHostPID_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{HostPID: true},
			},
		},
	}
	result := CheckHostPID(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckContainerHostPort_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", Ports: []corev1.ContainerPort{{HostPort: 8080}}},
					},
				},
			},
		},
	}
	result := CheckContainerHostPort(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- Capability checks ---

func TestCheckSysAdmin_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "c1",
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"SYS_ADMIN"},
								},
							},
						},
					},
				},
			},
		},
	}
	result := CheckSysAdmin(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysAdmin_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c1"}},
				},
			},
		},
	}
	result := CheckSysAdmin(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysAdmin_AllCapability(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "c1",
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"ALL"},
								},
							},
						},
					},
				},
			},
		},
	}
	result := CheckSysAdmin(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for ALL capability, got %s", result.ComplianceStatus)
	}
}

func TestCheckCapabilities_AllTypes(t *testing.T) {
	tests := []struct {
		name    string
		cap     string
		checkFn checks.CheckFunc
	}{
		{"NET_ADMIN", "NET_ADMIN", CheckNetAdmin},
		{"NET_RAW", "NET_RAW", CheckNetRaw},
		{"IPC_LOCK", "IPC_LOCK", CheckIPCLock},
		{"BPF", "BPF", CheckBPF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources := &checks.DiscoveredResources{
				Pods: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "c1",
									SecurityContext: &corev1.SecurityContext{
										Capabilities: &corev1.Capabilities{
											Add: []corev1.Capability{corev1.Capability(tt.cap)},
										},
									},
								},
							},
						},
					},
				},
			}
			result := tt.checkFn(resources)
			if result.ComplianceStatus != "NonCompliant" {
				t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
			}
		})
	}
}

// --- Security context checks ---

func TestCheckNonRootUser_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c1"}},
				},
			},
		},
	}
	result := CheckNonRootUser(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNonRootUser_CompliantViaRunAsNonRoot(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: testutil.BoolPtr(true)}},
					},
				},
			},
		},
	}
	result := CheckNonRootUser(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNonRootUser_CompliantViaRunAsUser(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{RunAsUser: testutil.Int64Ptr(1000)}},
					},
				},
			},
		},
	}
	result := CheckNonRootUser(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant via RunAsUser!=0, got %s", result.ComplianceStatus)
	}
}

func TestCheckNonRootUser_NonCompliantRunAsUserZero(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{RunAsUser: testutil.Int64Ptr(0)}},
					},
				},
			},
		},
	}
	result := CheckNonRootUser(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for RunAsUser=0, got %s", result.ComplianceStatus)
	}
}

func TestCheckNonRootUser_PodLevel(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: testutil.BoolPtr(true)},
					Containers:      []corev1.Container{{Name: "c1"}},
				},
			},
		},
	}
	result := CheckNonRootUser(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPrivilegeEscalation_ExplicitTrue(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: testutil.BoolPtr(true)}},
					},
				},
			},
		},
	}
	result := CheckPrivilegeEscalation(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPrivilegeEscalation_Nil(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c1"}},
				},
			},
		},
	}
	result := CheckPrivilegeEscalation(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for nil AllowPrivilegeEscalation, got %s", result.ComplianceStatus)
	}
}

func TestCheckPrivilegeEscalation_ExplicitFalse(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: testutil.BoolPtr(false)}},
					},
				},
			},
		},
	}
	result := CheckPrivilegeEscalation(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckReadOnlyFilesystem_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c1"}},
				},
			},
		},
	}
	result := CheckReadOnlyFilesystem(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- 1337 UID checks ---

func TestCheck1337UID_PodLevel_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsUser: testutil.Int64Ptr(1337)},
					Containers:      []corev1.Container{{Name: "c1"}},
				},
			},
		},
	}
	result := Check1337UID(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheck1337UID_ContainerLevel_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{RunAsUser: testutil.Int64Ptr(1337)}},
					},
				},
			},
		},
	}
	result := Check1337UID(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (certsuite only checks pod level), got %s", result.ComplianceStatus)
	}
}

func TestCheck1337UID_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsUser: testutil.Int64Ptr(1000)},
					Containers:      []corev1.Container{{Name: "c1"}},
				},
			},
		},
	}
	result := Check1337UID(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

// --- RBAC checks ---

func TestCheckServiceAccount_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "default"},
			},
		},
	}
	result := CheckServiceAccount(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckServiceAccount_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "my-sa"},
			},
		},
	}
	result := CheckServiceAccount(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckRoleBindings_DefaultSA(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "default"},
			},
		},
		Namespaces: []string{"ns1"},
	}
	result := CheckRoleBindings(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for default SA, got %s", result.ComplianceStatus)
	}
}

func TestCheckRoleBindings_CrossNamespace(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "my-sa"},
			},
		},
		RoleBindings: []rbacv1.RoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "rb1", Namespace: "other-ns"},
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "my-sa", Namespace: "ns1"},
				},
			},
		},
		Namespaces: []string{"ns1"},
	}
	result := CheckRoleBindings(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckClusterRoleBindings_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "my-sa"},
			},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "crb1"},
				RoleRef:    rbacv1.RoleRef{Name: "admin"},
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "my-sa", Namespace: "ns1"},
				},
			},
		},
	}
	result := CheckClusterRoleBindings(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckAutomountToken_DefaultSA(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "default"},
			},
		},
	}
	result := CheckAutomountToken(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for default SA, got %s", result.ComplianceStatus)
	}
}

func TestCheckAutomountToken_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "my-sa"},
			},
		},
		ServiceAccounts: []corev1.ServiceAccount{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "my-sa", Namespace: "ns1"},
			},
		},
	}
	result := CheckAutomountToken(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckAutomountToken_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					ServiceAccountName:           "my-sa",
					AutomountServiceAccountToken: testutil.BoolPtr(false),
				},
			},
		},
	}
	result := CheckAutomountToken(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

// --- Service checks ---

func TestCheckNodePortService_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Services: []corev1.Service{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort},
			},
		},
	}
	result := CheckNodePortService(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNodePortService_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Services: []corev1.Service{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "svc1", Namespace: "ns1"},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
			},
		},
	}
	result := CheckNodePortService(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

// --- SCC checks ---

func TestCheckSecurityContext_Privileged(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{Privileged: testutil.BoolPtr(true)}},
					},
				},
			},
		},
	}
	result := CheckSecurityContext(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSecurityContext_DangerousCap(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "c1",
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
							},
						},
					},
				},
			},
		},
	}
	result := CheckSecurityContext(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for dangerous cap, got %s", result.ComplianceStatus)
	}
}

func TestCheckSecurityContext_Restricted(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: testutil.BoolPtr(true)},
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{
							RunAsNonRoot: testutil.BoolPtr(true),
						}},
					},
				},
			},
		},
	}
	result := CheckSecurityContext(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for restricted container, got %s", result.ComplianceStatus)
	}
}

// --- Pod Requests checks ---

func TestCheckPodRequests_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
				}},
			},
		}},
	}
	result := CheckPodRequests(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodRequests_NonCompliant_NoCPU(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
				}},
			},
		}},
	}
	result := CheckPodRequests(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodRequests_NonCompliant_NoRequests(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckPodRequests(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- SYS_PTRACE checks ---

func TestCheckSysPtrace_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				ShareProcessNamespace: testutil.BoolPtr(true),
				Containers: []corev1.Container{{
					Name: "c1",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"SYS_PTRACE"},
						},
					},
				}},
			},
		}},
	}
	result := CheckSysPtrace(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysPtrace_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				ShareProcessNamespace: testutil.BoolPtr(true),
				Containers:            []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckSysPtrace(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysPtrace_NoSharedNS_Skipped(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckSysPtrace(resources)
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- CRD Role checks ---

func TestCheckCrdRoles_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Group: "example.com",
				Names: apiextv1.CustomResourceDefinitionNames{
					Plural:   "widgets",
					Singular: "widget",
				},
			},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "role1", Namespace: "ns1"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"example.com"},
				Resources: []string{"widgets"},
				Verbs:     []string{"get", "list"},
			}},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckCrdRoles(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckCrdRoles_NonCompliant(t *testing.T) {
	// A role that has both CRD and non-CRD rules should be non-compliant
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Group: "example.com",
				Names: apiextv1.CustomResourceDefinitionNames{Plural: "widgets"},
			},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "role1", Namespace: "ns1"},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"example.com"},
					Resources: []string{"widgets"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckCrdRoles(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckCrdRoles_NoCrdRules_Skipped(t *testing.T) {
	// A role that doesn't touch any CRD resources should be skipped (compliant)
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Group: "example.com",
				Names: apiextv1.CustomResourceDefinitionNames{Plural: "widgets"},
			},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "role1", Namespace: "ns1"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			}},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckCrdRoles(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for role not touching CRD resources, got %s", result.ComplianceStatus)
	}
}

func TestCheckCrdRoles_OutOfNamespace_Skipped(t *testing.T) {
	// A role not in a target namespace should be skipped
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Group: "example.com",
				Names: apiextv1.CustomResourceDefinitionNames{Plural: "widgets"},
			},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "role1", Namespace: "other-ns"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"example.com"},
				Resources: []string{"widgets"},
				Verbs:     []string{"get"},
			}},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckCrdRoles(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for role outside target namespaces, got %s", result.ComplianceStatus)
	}
}

// --- SYS_NICE realtime checks ---

func TestCheckSysNiceRealtime_Skipped_NoPods(t *testing.T) {
	resources := &checks.DiscoveredResources{}
	result := CheckSysNiceRealtime(resources)
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysNiceRealtime_Skipped_NoRTNodes(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec:       corev1.PodSpec{NodeName: "node1", Containers: []corev1.Container{{Name: "c1"}}},
		}},
		Nodes: []corev1.Node{{
			ObjectMeta: metav1.ObjectMeta{Name: "node1"},
			Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KernelVersion: "5.14.0-284.el9.x86_64"}},
		}},
	}
	result := CheckSysNiceRealtime(resources)
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysNiceRealtime_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec:       corev1.PodSpec{NodeName: "node1", Containers: []corev1.Container{{Name: "c1"}}},
		}},
		Nodes: []corev1.Node{{
			ObjectMeta: metav1.ObjectMeta{Name: "node1"},
			Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KernelVersion: "5.14.0-284.rt14.309.el9_2.x86_64"}},
		}},
	}
	result := CheckSysNiceRealtime(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- CheckSecurityContext additional scenarios (from certsuite securitycontextcontainer_test.go) ---

func TestCheckSecurityContext_AllowPrivilegeEscalation(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: testutil.BoolPtr(true),
						}},
					},
				},
			},
		},
	}
	result := CheckSecurityContext(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for AllowPrivilegeEscalation=true (category 2), got %s", result.ComplianceStatus)
	}
}

func TestCheckSecurityContext_DropAll_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "c1", SecurityContext: &corev1.SecurityContext{
							RunAsNonRoot: testutil.BoolPtr(true),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						}},
					},
				},
			},
		},
	}
	result := CheckSecurityContext(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for RunAsNonRoot+Drop ALL (category 1), got %s", result.ComplianceStatus)
	}
}

func TestCheckSecurityContext_MultipleContainersMixed(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "restricted", SecurityContext: &corev1.SecurityContext{
							RunAsNonRoot: testutil.BoolPtr(true),
						}},
						{Name: "privileged", SecurityContext: &corev1.SecurityContext{
							Privileged: testutil.BoolPtr(true),
						}},
					},
				},
			},
		},
	}
	result := CheckSecurityContext(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Errorf("expected exactly 1 detail for the privileged container, got %d", len(result.Details))
	}
}

// --- CheckPodRequests additional scenarios (from certsuite resources_test.go) ---

func TestCheckPodRequests_NonCompliant_NoMemory(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU: resource.MustParse("100m"),
						},
					},
				}},
			},
		}},
	}
	result := CheckPodRequests(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for missing memory request, got %s", result.ComplianceStatus)
	}
}

// --- CheckAutomountToken additional scenarios (from certsuite rbac/automount_test.go) ---

func TestCheckAutomountToken_PodNil_SAFalse_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "my-sa"},
			},
		},
		ServiceAccounts: []corev1.ServiceAccount{
			{
				ObjectMeta:                   metav1.ObjectMeta{Name: "my-sa", Namespace: "ns1"},
				AutomountServiceAccountToken: testutil.BoolPtr(false),
			},
		},
	}
	result := CheckAutomountToken(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (pod nil, SA false), got %s", result.ComplianceStatus)
	}
}

func TestCheckAutomountToken_PodNil_SATrue_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec:       corev1.PodSpec{ServiceAccountName: "my-sa"},
			},
		},
		ServiceAccounts: []corev1.ServiceAccount{
			{
				ObjectMeta:                   metav1.ObjectMeta{Name: "my-sa", Namespace: "ns1"},
				AutomountServiceAccountToken: testutil.BoolPtr(true),
			},
		},
	}
	result := CheckAutomountToken(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (pod nil, SA true), got %s", result.ComplianceStatus)
	}
}

func TestCheckAutomountToken_PodTrue_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
				Spec: corev1.PodSpec{
					ServiceAccountName:           "my-sa",
					AutomountServiceAccountToken: testutil.BoolPtr(true),
				},
			},
		},
		ServiceAccounts: []corev1.ServiceAccount{
			{
				ObjectMeta:                   metav1.ObjectMeta{Name: "my-sa", Namespace: "ns1"},
				AutomountServiceAccountToken: testutil.BoolPtr(false),
			},
		},
	}
	result := CheckAutomountToken(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (pod explicit true overrides SA false), got %s", result.ComplianceStatus)
	}
}

// --- CheckCrdRoles additional scenarios (from certsuite rbac/roles_test.go) ---

func TestCheckCrdRoles_MultipleRulesMultipleGroups(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Group: "example.com",
				Names: apiextv1.CustomResourceDefinitionNames{Plural: "widgets"},
			},
		}},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "role1", Namespace: "ns1"},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"example.com"},
					Resources: []string{"widgets"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"deployments"},
					Verbs:     []string{"get"},
				},
			},
		}},
		Namespaces: []string{"ns1"},
	}
	result := CheckCrdRoles(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for non-CRD resource 'deployments', got %s", result.ComplianceStatus)
	}
	nonCompliantCount := 0
	for _, d := range result.Details {
		if !d.Compliant {
			nonCompliantCount++
		}
	}
	if nonCompliantCount != 1 {
		t.Errorf("expected 1 non-compliant detail for the role, got %d", nonCompliantCount)
	}
}

// --- CheckNamespace additional scenarios ---

func TestCheckNamespace_DefaultNS_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "default"}},
		},
	}
	result := CheckNamespace(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for pod in 'default' namespace, got %s", result.ComplianceStatus)
	}
}

func TestCheckNamespace_DefaultPrefixNS_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "default-test"}},
		},
	}
	result := CheckNamespace(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for pod in 'default-test' namespace, got %s", result.ComplianceStatus)
	}
}

func TestCheckNamespace_OpenShiftNS_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "openshift-monitoring"}},
		},
	}
	result := CheckNamespace(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for pod in 'openshift-monitoring' namespace, got %s", result.ComplianceStatus)
	}
}

func TestCheckNamespace_IstioNS_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "istio-system"}},
		},
	}
	result := CheckNamespace(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for pod in 'istio-system' namespace, got %s", result.ComplianceStatus)
	}
}

func TestCheckNamespace_AspenMeshNS_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "aspenmesh-system"}},
		},
	}
	result := CheckNamespace(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for pod in 'aspenmesh-system' namespace, got %s", result.ComplianceStatus)
	}
}

func TestCheckNamespace_CustomNS_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "my-app"}},
		},
	}
	result := CheckNamespace(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for pod in 'my-app' namespace, got %s", result.ComplianceStatus)
	}
}

// --- Namespace ResourceQuota checks ---

func TestCheckNamespaceResourceQuota_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"}},
		},
		ResourceQuotas: []corev1.ResourceQuota{
			{ObjectMeta: metav1.ObjectMeta{Name: "quota1", Namespace: "ns1"}},
		},
	}
	result := CheckNamespaceResourceQuota(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNamespaceResourceQuota_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"}},
		},
	}
	result := CheckNamespaceResourceQuota(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNamespaceResourceQuota_NoPods(t *testing.T) {
	result := CheckNamespaceResourceQuota(&checks.DiscoveredResources{})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Compliant for no pods, got %s", result.ComplianceStatus)
	}
}

func TestCheckNamespaceResourceQuota_MultiplePods_MixedNamespaces(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "ns2"}},
		},
		ResourceQuotas: []corev1.ResourceQuota{
			{ObjectMeta: metav1.ObjectMeta{Name: "quota1", Namespace: "ns1"}},
		},
	}
	result := CheckNamespaceResourceQuota(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (ns2 has no quota), got %s", result.ComplianceStatus)
	}
	// Should have exactly 1 non-compliant detail for pod2 in ns2
	nonCompliantCount := 0
	for _, d := range result.Details {
		if !d.Compliant {
			nonCompliantCount++
		}
	}
	if nonCompliantCount != 1 {
		t.Errorf("expected 1 non-compliant detail, got %d", nonCompliantCount)
	}
}

func TestCheckNamespaceResourceQuota_AllPodsHaveQuota(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "ns2"}},
		},
		ResourceQuotas: []corev1.ResourceQuota{
			{ObjectMeta: metav1.ObjectMeta{Name: "quota1", Namespace: "ns1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "quota2", Namespace: "ns2"}},
		},
	}
	result := CheckNamespaceResourceQuota(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

// --- One process per container checks ---

func TestCheckOneProcess_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				NodeName:   "node1",
				Containers: []corev1.Container{{Name: "c1"}},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{Name: "c1", ContainerID: "cri-o://abc123"}},
			},
		}},
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host crictl inspect --output go-template --template '{{.info.pid}}' abc123 2>/dev/null": {stdout: "12345"},
				"lsns -p 12345 -t pid -n": {stdout: "4026531836 pid 1 12345 /usr/bin/myapp"},
			},
		},
	}
	result := CheckOneProcess(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckOneProcess_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				NodeName:   "node1",
				Containers: []corev1.Container{{Name: "c1"}},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{Name: "c1", ContainerID: "cri-o://abc123"}},
			},
		}},
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host crictl inspect --output go-template --template '{{.info.pid}}' abc123 2>/dev/null": {stdout: "12345"},
				"lsns -p 12345 -t pid -n": {stdout: "4026531836 pid 3 12345 /usr/bin/myapp"},
			},
		},
	}
	result := CheckOneProcess(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- No SSHD checks ---

func TestCheckNoSSHD_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec:       corev1.PodSpec{NodeName: "node1"},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{Name: "c1", ContainerID: "cri-o://abc123"}},
			},
		}},
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host crictl inspect --output go-template --template '{{.info.pid}}' abc123 2>/dev/null": {stdout: "12345"},
				"nsenter -t 12345 -n ss -tpln": {stdout: "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\nLISTEN 0      128    0.0.0.0:8080         0.0.0.0:*     users:((\"myapp\",pid=12345,fd=3))\n"},
			},
		},
	}
	result := CheckNoSSHD(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckNoSSHD_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec:       corev1.PodSpec{NodeName: "node1"},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{Name: "c1", ContainerID: "cri-o://abc123"}},
			},
		}},
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host crictl inspect --output go-template --template '{{.info.pid}}' abc123 2>/dev/null": {stdout: "12345"},
				"nsenter -t 12345 -n ss -tpln": {stdout: "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\nLISTEN 0      128    0.0.0.0:22           0.0.0.0:*     users:((\"sshd\",pid=12345,fd=3))\n"},
			},
		},
	}
	result := CheckNoSSHD(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysNiceRealtime_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				NodeName: "node1",
				Containers: []corev1.Container{{
					Name: "c1",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"SYS_NICE"},
						},
					},
				}},
			},
		}},
		Nodes: []corev1.Node{{
			ObjectMeta: metav1.ObjectMeta{Name: "node1"},
			Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KernelVersion: "5.14.0-284.rt14.309.el9_2.x86_64"}},
		}},
	}
	result := CheckSysNiceRealtime(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}
