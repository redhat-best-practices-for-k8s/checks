package certification

import (
	"testing"

	"github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// mockValidator implements checks.CertificationValidator for testing.
type mockValidator struct {
	containerCertified map[string]bool // key: "registry/repository:tag@digest"
	operatorCertified  map[string]bool // key: "csvName@ocpVersion"
	helmCertified      map[string]bool // key: "name@version"
}

func (m *mockValidator) IsContainerCertified(registry, repository, tag, digest string) bool {
	key := registry + "/" + repository + ":" + tag + "@" + digest
	return m.containerCertified[key]
}

func (m *mockValidator) IsOperatorCertified(csvName, ocpVersion string) bool {
	key := csvName + "@" + ocpVersion
	return m.operatorCertified[key]
}

func (m *mockValidator) IsHelmChartCertified(chartName, chartVersion, kubeVersion string) bool {
	key := chartName + "@" + chartVersion
	return m.helmCertified[key]
}

// --- Helm Version Tests ---

func TestCheckHelmVersion_NoReleases(t *testing.T) {
	result := CheckHelmVersion(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckHelmVersion_NoClientset(t *testing.T) {
	resources := &checks.DiscoveredResources{
		HelmChartReleases: []checks.HelmChartRelease{{Name: "my-chart", Namespace: "ns1", Version: "1.0.0"}},
	}
	result := CheckHelmVersion(resources)
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckHelmVersion_Compliant_NoTiller(t *testing.T) {
	client := fake.NewClientset()
	resources := &checks.DiscoveredResources{
		HelmChartReleases: []checks.HelmChartRelease{
			{Name: "my-chart", Namespace: "ns1", Version: "1.0.0"},
			{Name: "other-chart", Namespace: "ns2", Version: "2.0.0"},
		},
		K8sClientset: client,
	}
	result := CheckHelmVersion(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 2 {
		t.Errorf("expected 2 details, got %d", len(result.Details))
	}
}

func TestCheckHelmVersion_NonCompliant_TillerFound(t *testing.T) {
	tillerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tiller-deploy-abc",
			Namespace: "kube-system",
			Labels:    map[string]string{"app": "helm", "name": "tiller"},
		},
	}
	client := fake.NewClientset(tillerPod)
	resources := &checks.DiscoveredResources{
		HelmChartReleases: []checks.HelmChartRelease{
			{Name: "my-chart", Namespace: "ns1", Version: "1.0.0"},
		},
		K8sClientset: client,
	}
	result := CheckHelmVersion(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Errorf("expected 1 detail, got %d", len(result.Details))
	}
	if result.Details[0].Name != "tiller-deploy-abc" {
		t.Errorf("expected tiller pod name, got %s", result.Details[0].Name)
	}
}

// --- Container Certified Tests ---

func TestCheckContainerCertified_NoValidator(t *testing.T) {
	result := CheckContainerCertified(&checks.DiscoveredResources{
		Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}},
	})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckContainerCertified_NoPods(t *testing.T) {
	result := CheckContainerCertified(&checks.DiscoveredResources{
		CertValidator: &mockValidator{},
	})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckContainerCertified_Compliant(t *testing.T) {
	v := &mockValidator{
		containerCertified: map[string]bool{
			"registry.example.com/repo/myapp:v1.0@sha256:abc123": true,
		},
	}
	resources := &checks.DiscoveredResources{
		CertValidator: v,
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "c1",
					Image: "registry.example.com/repo/myapp:v1.0",
				}},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:    "c1",
					ImageID: "registry.example.com/repo/myapp@sha256:abc123",
				}},
			},
		}},
	}
	result := CheckContainerCertified(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckContainerCertified_NonCompliant_MissingDigest(t *testing.T) {
	v := &mockValidator{containerCertified: map[string]bool{}}
	resources := &checks.DiscoveredResources{
		CertValidator: v,
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "c1",
					Image: "registry.example.com/repo/myapp:v1.0",
				}},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:    "c1",
					ImageID: "",
				}},
			},
		}},
	}
	result := CheckContainerCertified(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckContainerCertified_NonCompliant_NotCertified(t *testing.T) {
	v := &mockValidator{containerCertified: map[string]bool{}}
	resources := &checks.DiscoveredResources{
		CertValidator: v,
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "c1",
					Image: "registry.example.com/repo/myapp:v1.0",
				}},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:    "c1",
					ImageID: "registry.example.com/repo/myapp@sha256:abc123",
				}},
			},
		}},
	}
	result := CheckContainerCertified(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- Operator Certified Tests ---

func TestCheckOperatorCertified_NoValidator(t *testing.T) {
	result := CheckOperatorCertified(&checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{{ObjectMeta: metav1.ObjectMeta{Name: "op1"}}},
	})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckOperatorCertified_NoCSVs(t *testing.T) {
	result := CheckOperatorCertified(&checks.DiscoveredResources{
		CertValidator: &mockValidator{},
	})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckOperatorCertified_Compliant(t *testing.T) {
	v := &mockValidator{
		operatorCertified: map[string]bool{
			"my-operator.v1.0.0@4.13": true,
		},
	}
	resources := &checks.DiscoveredResources{
		CertValidator:    v,
		OpenshiftVersion: "4.13.5",
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{Name: "my-operator.v1.0.0", Namespace: "ns1"},
		}},
	}
	result := CheckOperatorCertified(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckOperatorCertified_NonCompliant(t *testing.T) {
	v := &mockValidator{operatorCertified: map[string]bool{}}
	resources := &checks.DiscoveredResources{
		CertValidator:    v,
		OpenshiftVersion: "4.13.5",
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{Name: "my-operator.v1.0.0", Namespace: "ns1"},
		}},
	}
	result := CheckOperatorCertified(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckOperatorCertified_EmptyVersion(t *testing.T) {
	v := &mockValidator{
		operatorCertified: map[string]bool{
			"my-operator.v1.0.0@": true,
		},
	}
	resources := &checks.DiscoveredResources{
		CertValidator: v,
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{Name: "my-operator.v1.0.0", Namespace: "ns1"},
		}},
	}
	result := CheckOperatorCertified(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

// --- Helm Chart Certified Tests ---

func TestCheckHelmChartCertified_NoValidator(t *testing.T) {
	result := CheckHelmChartCertified(&checks.DiscoveredResources{
		HelmChartReleases: []checks.HelmChartRelease{{Name: "chart1"}},
	})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckHelmChartCertified_NoReleases(t *testing.T) {
	result := CheckHelmChartCertified(&checks.DiscoveredResources{
		CertValidator: &mockValidator{},
	})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

func TestCheckHelmChartCertified_Compliant(t *testing.T) {
	v := &mockValidator{
		helmCertified: map[string]bool{
			"my-chart@1.0.0": true,
		},
	}
	resources := &checks.DiscoveredResources{
		CertValidator: v,
		K8sVersion:    "1.27.0",
		HelmChartReleases: []checks.HelmChartRelease{
			{Name: "my-chart", Namespace: "ns1", Version: "1.0.0"},
		},
	}
	result := CheckHelmChartCertified(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHelmChartCertified_NonCompliant(t *testing.T) {
	v := &mockValidator{helmCertified: map[string]bool{}}
	resources := &checks.DiscoveredResources{
		CertValidator: v,
		K8sVersion:    "1.27.0",
		HelmChartReleases: []checks.HelmChartRelease{
			{Name: "my-chart", Namespace: "ns1", Version: "1.0.0"},
		},
	}
	result := CheckHelmChartCertified(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckHelmChartCertified_MixedCompliance(t *testing.T) {
	v := &mockValidator{
		helmCertified: map[string]bool{
			"good-chart@1.0.0": true,
		},
	}
	resources := &checks.DiscoveredResources{
		CertValidator: v,
		K8sVersion:    "1.27.0",
		HelmChartReleases: []checks.HelmChartRelease{
			{Name: "good-chart", Namespace: "ns1", Version: "1.0.0"},
			{Name: "bad-chart", Namespace: "ns1", Version: "2.0.0"},
		},
	}
	result := CheckHelmChartCertified(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 2 {
		t.Fatalf("expected 2 details, got %d", len(result.Details))
	}
	if !result.Details[0].Compliant {
		t.Error("expected first detail to be compliant")
	}
	if result.Details[1].Compliant {
		t.Error("expected second detail to be non-compliant")
	}
}

// --- Image Parser Tests ---

func TestParseContainerImage_WithTagAndDigest(t *testing.T) {
	registry, repository, tag, digest := parseContainerImage(
		"registry.example.com/repo/myapp:v1.0",
		"registry.example.com/repo/myapp@sha256:abc123",
	)
	if registry != "registry.example.com" {
		t.Errorf("expected registry.example.com, got %s", registry)
	}
	if repository != "repo/myapp" {
		t.Errorf("expected repo/myapp, got %s", repository)
	}
	if tag != "v1.0" {
		t.Errorf("expected v1.0, got %s", tag)
	}
	if digest != "sha256:abc123" {
		t.Errorf("expected sha256:abc123, got %s", digest)
	}
}

func TestParseContainerImage_NoDigest(t *testing.T) {
	registry, repository, tag, digest := parseContainerImage(
		"registry.example.com/repo/myapp:v1.0",
		"",
	)
	if registry != "registry.example.com" {
		t.Errorf("expected registry.example.com, got %s", registry)
	}
	if repository != "repo/myapp" {
		t.Errorf("expected repo/myapp, got %s", repository)
	}
	if tag != "v1.0" {
		t.Errorf("expected v1.0, got %s", tag)
	}
	if digest != "" {
		t.Errorf("expected empty digest, got %s", digest)
	}
}

func TestParseContainerImage_ShortImage(t *testing.T) {
	registry, repository, tag, _ := parseContainerImage(
		"myapp:latest",
		"",
	)
	// Short image with no slash: repository is the first capture, registry is empty
	if repository != "myapp" {
		t.Errorf("expected myapp, got %s", repository)
	}
	if registry != "" {
		t.Errorf("expected empty registry, got %s", registry)
	}
	if tag != "latest" {
		t.Errorf("expected latest, got %s", tag)
	}
}

// --- extractOCPMinorVersion Tests ---

func TestExtractOCPMinorVersion(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"4.13.5", "4.13"},
		{"4.12.0", "4.12"},
		{"4.14", "4.14"},
		{"", ""},
		{"5", "5"},
	}
	for _, tc := range tests {
		got := extractOCPMinorVersion(tc.input)
		if got != tc.want {
			t.Errorf("extractOCPMinorVersion(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
