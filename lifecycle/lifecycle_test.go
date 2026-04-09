package lifecycle

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
)

// --- Probe checks ---

func TestCheckStartupProbe_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:         "c1",
					StartupProbe: &corev1.Probe{},
				}},
			},
		}},
	}
	result := CheckStartupProbe(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckStartupProbe_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckStartupProbe(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckReadinessProbe_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckReadinessProbe(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckLivenessProbe_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckLivenessProbe(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckProbes_NoPods(t *testing.T) {
	resources := &checks.DiscoveredResources{}
	for _, fn := range []checks.CheckFunc{CheckStartupProbe, CheckReadinessProbe, CheckLivenessProbe} {
		result := fn(resources)
		if result.ComplianceStatus != checks.StatusCompliant {
			t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
		}
	}
}

// --- Hook checks ---

func TestCheckPreStop_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckPreStop(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPreStop_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Lifecycle: &corev1.Lifecycle{
						PreStop: &corev1.LifecycleHandler{
							Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-c", "sleep 5"}},
						},
					},
				}},
			},
		}},
	}
	result := CheckPreStop(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPostStart_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c1"}},
			},
		}},
	}
	result := CheckPostStart(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- Pod checks ---

func TestCheckImagePullPolicy_IfNotPresent_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "c1",
					Image:           "nginx:1.21",
					ImagePullPolicy: corev1.PullIfNotPresent,
				}},
			},
		}},
	}
	result := CheckImagePullPolicy(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckImagePullPolicy_Always_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "c1",
					Image:           "nginx:latest",
					ImagePullPolicy: corev1.PullAlways,
				}},
			},
		}},
	}
	result := CheckImagePullPolicy(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckImagePullPolicy_Never_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "c1",
					Image:           "nginx:1.21",
					ImagePullPolicy: corev1.PullNever,
				}},
			},
		}},
	}
	result := CheckImagePullPolicy(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodOwnerType_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rs1"}},
			},
		}},
	}
	result := CheckPodOwnerType(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodOwnerType_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
		}},
	}
	result := CheckPodOwnerType(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- CheckPodOwnerType additional scenarios (from certsuite ownerreference_test.go) ---

func TestCheckPodOwnerType_StatefulSet_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: "sts1"}},
			},
		}},
	}
	result := CheckPodOwnerType(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for StatefulSet owner, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodOwnerType_DaemonSet_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: "ds1"}},
			},
		}},
	}
	result := CheckPodOwnerType(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant for DaemonSet owner, got %s", result.ComplianceStatus)
	}
}

func TestCheckHighAvailability_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec:       appsv1.DeploymentSpec{Replicas: testutil.Int32Ptr(3)},
		}},
	}
	result := CheckHighAvailability(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHighAvailability_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec:       appsv1.DeploymentSpec{Replicas: testutil.Int32Ptr(1)},
		}},
	}
	result := CheckHighAvailability(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHighAvailability_NilReplicas(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec:       appsv1.DeploymentSpec{},
		}},
	}
	result := CheckHighAvailability(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (nil replicas defaults to 1), got %s", result.ComplianceStatus)
	}
}

func TestCheckCPUIsolation_Compliant(t *testing.T) {
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
				}},
			},
		}},
	}
	result := CheckCPUIsolation(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckCPUIsolation_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "c1",
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
						Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
					},
				}},
			},
		}},
	}
	result := CheckCPUIsolation(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckTolerationBypass_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Tolerations: []corev1.Toleration{{
					Key:    "node-role.kubernetes.io/master",
					Effect: corev1.TaintEffectNoSchedule,
				}},
			},
		}},
	}
	result := CheckTolerationBypass(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckTolerationBypass_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Tolerations: []corev1.Toleration{{
					Key:    "some-other-taint",
					Effect: corev1.TaintEffectNoSchedule,
				}},
			},
		}},
	}
	result := CheckTolerationBypass(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPVReclaimPolicy_Delete_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		PersistentVolumes: []corev1.PersistentVolume{{
			ObjectMeta: metav1.ObjectMeta{Name: "pv1"},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
			},
		}},
	}
	result := CheckPVReclaimPolicy(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPVReclaimPolicy_Retain_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		PersistentVolumes: []corev1.PersistentVolume{{
			ObjectMeta: metav1.ObjectMeta{Name: "pv1"},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			},
		}},
	}
	result := CheckPVReclaimPolicy(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodScheduling_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec:       corev1.PodSpec{},
		}},
	}
	result := CheckPodScheduling(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodScheduling_Compliant_NodeSelector(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				NodeSelector: map[string]string{"role": "worker"},
			},
		}},
	}
	result := CheckPodScheduling(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckAffinityRequired_PodAffinity_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				Labels: map[string]string{"AffinityRequired": "true"},
			},
			Spec: corev1.PodSpec{
				Affinity: &corev1.Affinity{
					PodAffinity: &corev1.PodAffinity{},
				},
			},
		}},
	}
	result := CheckAffinityRequired(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckAffinityRequired_NodeAffinity_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				Labels: map[string]string{"AffinityRequired": "true"},
			},
			Spec: corev1.PodSpec{
				Affinity: &corev1.Affinity{
					NodeAffinity: &corev1.NodeAffinity{},
				},
			},
		}},
	}
	result := CheckAffinityRequired(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckAffinityRequired_NoAffinity_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				Labels: map[string]string{"AffinityRequired": "true"},
			},
			Spec: corev1.PodSpec{},
		}},
	}
	result := CheckAffinityRequired(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckAffinityRequired_AntiAffinity_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pod1", Namespace: "ns1",
				Labels: map[string]string{"AffinityRequired": "true"},
			},
			Spec: corev1.PodSpec{
				Affinity: &corev1.Affinity{
					PodAntiAffinity: &corev1.PodAntiAffinity{},
					PodAffinity:     &corev1.PodAffinity{},
				},
			},
		}},
	}
	result := CheckAffinityRequired(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckAffinityRequired_NoLabel_Skipped(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec:       corev1.PodSpec{},
		}},
	}
	result := CheckAffinityRequired(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (no pods with label), got %s", result.ComplianceStatus)
	}
}

// --- Topology Spread Constraints ---

func TestCheckTopologySpreadConstraints_NoConstraints_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{},
			},
		}},
	}
	result := CheckTopologySpreadConstraints(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (no constraints), got %s", result.ComplianceStatus)
	}
}

func TestCheckTopologySpreadConstraints_BothKeys_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
							{TopologyKey: "kubernetes.io/hostname"},
							{TopologyKey: "topology.kubernetes.io/zone"},
						},
					},
				},
			},
		}},
	}
	result := CheckTopologySpreadConstraints(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckTopologySpreadConstraints_MissingZone_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "deploy1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
							{TopologyKey: "kubernetes.io/hostname"},
						},
					},
				},
			},
		}},
	}
	result := CheckTopologySpreadConstraints(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- StorageProvisioner checks ---

func TestCheckStorageProvisioner_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		StorageClasses: []storagev1.StorageClass{{
			ObjectMeta:  metav1.ObjectMeta{Name: "ebs-sc"},
			Provisioner: "ebs.csi.aws.com",
		}},
	}
	result := CheckStorageProvisioner(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckStorageProvisioner_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		StorageClasses: []storagev1.StorageClass{{
			ObjectMeta:  metav1.ObjectMeta{Name: "local-sc"},
			Provisioner: "kubernetes.io/no-provisioner",
		}},
	}
	result := CheckStorageProvisioner(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckStorageProvisioner_Skipped(t *testing.T) {
	result := CheckStorageProvisioner(&checks.DiscoveredResources{})
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}
