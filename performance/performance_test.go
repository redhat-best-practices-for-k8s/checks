package performance

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// --- Memory limit ---

func TestCheckMemoryLimit_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
					},
				}},
			},
		}},
	}
	result := CheckMemoryLimit(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckMemoryLimit_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckMemoryLimit(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckMemoryLimit_NoPods(t *testing.T) {
	result := CheckMemoryLimit(&checks.DiscoveredResources{})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- Exclusive CPU pool ---

func TestCheckExclusiveCPUPool_Compliant_AllExclusive(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("2"),
							corev1.ResourceMemory: resource.MustParse("256Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("2"),
							corev1.ResourceMemory: resource.MustParse("256Mi"),
						},
					},
				}},
			},
		}},
	}
	result := CheckExclusiveCPUPool(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for all-exclusive pod, got %s", result.ComplianceStatus)
	}
}

func TestCheckExclusiveCPUPool_Compliant_AllShared(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
					},
				}},
			},
		}},
	}
	result := CheckExclusiveCPUPool(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for all-shared pod, got %s", result.ComplianceStatus)
	}
}

func TestCheckExclusiveCPUPool_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						// Exclusive: integer CPU, memory limits == requests (Guaranteed QoS)
						Name: "exclusive",
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("2"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("2"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
						},
					},
					{
						// Shared: no resource limits
						Name: "shared",
					},
				},
			},
		}},
	}
	result := CheckExclusiveCPUPool(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckExclusiveCPUPool_SingleContainer_MismatchedLimits_Compliant(t *testing.T) {
	// A single container with mismatched CPU req/lim is in the shared pool only.
	// No mixing occurs, so the pod is compliant.
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4")},
					},
				}},
			},
		}},
	}
	result := CheckExclusiveCPUPool(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (single container, no mixing), got %s", result.ComplianceStatus)
	}
}

func TestCheckExclusiveCPUPool_FractionalCPU_Skipped(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
					},
				}},
			},
		}},
	}
	result := CheckExclusiveCPUPool(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (fractional CPU not checked), got %s", result.ComplianceStatus)
	}
}

// --- Exclusive CPU pool additional scenarios (from certsuite resources_test.go) ---

func TestCheckExclusiveCPUPool_FractionalEqual(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m")},
					},
				}},
			},
		}},
	}
	result := CheckExclusiveCPUPool(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (fractional CPUs are skipped), got %s", result.ComplianceStatus)
	}
}

func TestCheckExclusiveCPUPool_MemoryMismatch(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("2"),
							corev1.ResourceMemory: resource.MustParse("512Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("2"),
							corev1.ResourceMemory: resource.MustParse("256Mi"),
						},
					},
				}},
			},
		}},
	}
	result := CheckExclusiveCPUPool(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (memory mismatch means container is in shared pool, single container means no mixing), got %s", result.ComplianceStatus)
	}
}

// --- RT apps no exec probes ---

func TestCheckRTAppsNoExecProbes_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				Annotations: map[string]string{"rt-app": "true"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"cat", "/tmp/healthy"}},
						},
					},
				}},
			},
		}},
	}
	result := CheckRTAppsNoExecProbes(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckRTAppsNoExecProbes_NonRT_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"cat", "/tmp/healthy"}},
						},
					},
				}},
			},
		}},
	}
	result := CheckRTAppsNoExecProbes(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (non-RT pod), got %s", result.ComplianceStatus)
	}
}

// --- Limited exec probes ---

func TestCheckLimitedExecProbes_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"cat", "/tmp/healthy"}},
						},
					},
				}},
			},
		}},
	}
	result := CheckLimitedExecProbes(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (1 probe < 10), got %s", result.ComplianceStatus)
	}
}

func TestCheckLimitedExecProbes_NonCompliant(t *testing.T) {
	var pods []corev1.Pod
	for i := 0; i < 4; i++ {
		pods = append(pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod%d", i), Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"true"}},
						},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"true"}},
						},
					},
					StartupProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"true"}},
						},
					},
				}},
			},
		})
	}
	resources := &checks.DiscoveredResources{Pods: pods}
	result := CheckLimitedExecProbes(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (12 probes >= 10), got %s", result.ComplianceStatus)
	}
}

// --- CPU pinning no exec probes ---

func TestCheckCPUPinningNoExecProbes_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/healthz"},
						},
					},
				}},
			},
		}},
	}
	result := CheckCPUPinningNoExecProbes(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (httpGet probe), got %s", result.ComplianceStatus)
	}
}

func TestCheckCPUPinningNoExecProbes_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"true"}},
						},
					},
				}},
			},
		}},
	}
	result := CheckCPUPinningNoExecProbes(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckCPUPinningNoExecProbes_NoCPUPinning_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{Command: []string{"true"}},
						},
					},
				}},
			},
		}},
	}
	result := CheckCPUPinningNoExecProbes(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (no CPU pinning), got %s", result.ComplianceStatus)
	}
}

// --- Max resources exec probes ---

func TestCheckMaxResourcesExecProbes_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					LivenessProbe: &corev1.Probe{
						ProbeHandler:  corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"true"}}},
						PeriodSeconds: 15,
					},
				}},
			},
		}},
	}
	result := CheckMaxResourcesExecProbes(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckMaxResourcesExecProbes_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					LivenessProbe: &corev1.Probe{
						ProbeHandler:  corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"true"}}},
						PeriodSeconds: 5,
					},
				}},
			},
		}},
	}
	result := CheckMaxResourcesExecProbes(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckMaxResourcesExecProbes_Skipped(t *testing.T) {
	resources := &checks.DiscoveredResources{}
	result := CheckMaxResourcesExecProbes(resources)
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckMaxResourcesExecProbes_NoExecProbes_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/healthz"},
						},
					},
				}},
			},
		}},
	}
	result := CheckMaxResourcesExecProbes(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}
