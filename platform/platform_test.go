package platform

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
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

// --- Hugepages 1Gi only ---

func TestCheckHugepages1GiOnly_Compliant(t *testing.T) {
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
	result := CheckHugepages1GiOnly(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHugepages1GiOnly_NonCompliant(t *testing.T) {
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
	result := CheckHugepages1GiOnly(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHugepages1GiOnly_Skipped(t *testing.T) {
	result := CheckHugepages1GiOnly(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- Boot params checks ---

func TestCheckBootParams_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/cmdline": {stdout: "BOOT_IMAGE=/vmlinuz root=/dev/sda1"},
			},
		},
	}
	result := CheckBootParams(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckBootParams_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/cmdline": {stdout: "BOOT_IMAGE=/vmlinuz hugepagesz=1G hugepages=4"},
			},
		},
	}
	result := CheckBootParams(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckBootParams_Skipped(t *testing.T) {
	result := CheckBootParams(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckBootParams_ProbeFailure(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/cmdline": {stdout: "", stderr: "", err: fmt.Errorf("connection timeout")},
			},
		},
	}
	result := CheckBootParams(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for probe failure, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Errorf("expected 1 detail entry for failed node, got %d", len(result.Details))
	}
}

// --- Hugepages (probe-based) ---

func TestCheckHugepages_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/cmdline": {stdout: "BOOT_IMAGE=/vmlinuz hugepagesz=1G"},
				"cat /host/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null": {stdout: "1024"},
			},
		},
	}
	result := CheckHugepages(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHugepages_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/cmdline": {stdout: "BOOT_IMAGE=/vmlinuz hugepagesz=1G"},
				"cat /host/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null": {stdout: "0"},
			},
		},
	}
	result := CheckHugepages(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHugepages_NoHugepagesInCmdline(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/cmdline": {stdout: "BOOT_IMAGE=/vmlinuz root=/dev/sda1"},
			},
		},
	}
	result := CheckHugepages(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (no hugepage boot params), got %s", result.ComplianceStatus)
	}
}

func TestCheckHugepages_ProbeFailure(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/cmdline": {stdout: "", stderr: "", err: fmt.Errorf("probe failed")},
			},
		},
	}
	result := CheckHugepages(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for probe failure, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Errorf("expected 1 detail entry for failed node, got %d", len(result.Details))
	}
}

// --- Sysctl checks ---

func TestCheckSysctl_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null": {stdout: "0"},
				"chroot /host sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null": {stdout: "0"},
				"chroot /host sysctl -n net.ipv4.conf.all.secure_redirects 2>/dev/null": {stdout: "1"},
				"chroot /host sysctl -n kernel.core_pattern 2>/dev/null":                {stdout: "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h"},
			},
		},
	}
	result := CheckSysctl(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysctl_NonCompliant_AcceptRedirects(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null": {stdout: "1"},
				"chroot /host sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null": {stdout: "0"},
				"chroot /host sysctl -n net.ipv4.conf.all.secure_redirects 2>/dev/null": {stdout: "1"},
				"chroot /host sysctl -n kernel.core_pattern 2>/dev/null":                {stdout: "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h"},
			},
		},
	}
	result := CheckSysctl(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysctl_NonCompliant_CorePattern(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null": {stdout: "0"},
				"chroot /host sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null": {stdout: "0"},
				"chroot /host sysctl -n net.ipv4.conf.all.secure_redirects 2>/dev/null": {stdout: "1"},
				"chroot /host sysctl -n kernel.core_pattern 2>/dev/null":                {stdout: "/tmp/core.%p"},
			},
		},
	}
	result := CheckSysctl(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysctl_Skipped(t *testing.T) {
	result := CheckSysctl(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckSysctl_ProbeFailure(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null": {stdout: "", stderr: "", err: fmt.Errorf("probe failed")},
			},
		},
	}
	result := CheckSysctl(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for probe failure, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Errorf("expected 1 detail entry for failed node, got %d", len(result.Details))
	}
}

// --- Tainted kernel checks ---

func TestCheckTainted_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/sys/kernel/tainted": {stdout: "0"},
			},
		},
	}
	result := CheckTainted(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckTainted_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/sys/kernel/tainted": {stdout: "4096"},
			},
		},
	}
	result := CheckTainted(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckTainted_Skipped(t *testing.T) {
	result := CheckTainted(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckTainted_ProbeFailure(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"cat /host/proc/sys/kernel/tainted": {stdout: "", stderr: "", err: fmt.Errorf("probe failed")},
			},
		},
	}
	result := CheckTainted(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for probe failure, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Errorf("expected 1 detail entry for failed node, got %d", len(result.Details))
	}
}

// --- SELinux Enforcing checks ---

func TestCheckSELinuxEnforcing_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host getenforce": {stdout: "Enforcing"},
			},
		},
	}
	result := CheckSELinuxEnforcing(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSELinuxEnforcing_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host getenforce": {stdout: "Permissive"},
			},
		},
	}
	result := CheckSELinuxEnforcing(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSELinuxEnforcing_Skipped(t *testing.T) {
	result := CheckSELinuxEnforcing(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckSELinuxEnforcing_ProbeFailure(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ProbePods: map[string]*corev1.Pod{"node1": makeProbePod("node1")},
		ProbeExecutor: &mockProbeExecutor{
			responses: map[string]mockProbeResponse{
				"chroot /host getenforce": {stdout: "", stderr: "", err: fmt.Errorf("probe failed")},
			},
		},
	}
	result := CheckSELinuxEnforcing(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant for probe failure, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Errorf("expected 1 detail entry for failed node, got %d", len(result.Details))
	}
}
