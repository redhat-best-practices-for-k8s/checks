package operator

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/operator-framework/api/pkg/lib/version"
	"github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeVersion(v string) version.OperatorVersion {
	return version.OperatorVersion{Version: semver.MustParse(v)}
}

// --- Install Status Succeeded ---

func TestCheckInstallStatusSucceeded_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{Name: "my-operator.v1.0.0", Namespace: "ns1"},
			Status:     v1alpha1.ClusterServiceVersionStatus{Phase: v1alpha1.CSVPhaseSucceeded},
		}},
	}
	result := CheckOperatorInstallStatusSucceeded(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckInstallStatusSucceeded_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{Name: "my-operator.v1.0.0", Namespace: "ns1"},
			Status:     v1alpha1.ClusterServiceVersionStatus{Phase: v1alpha1.CSVPhaseFailed},
		}},
	}
	result := CheckOperatorInstallStatusSucceeded(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckInstallStatusSucceeded_NoCSVs(t *testing.T) {
	result := CheckOperatorInstallStatusSucceeded(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- No SCC Access ---

func TestCheckNoSCCAccess_Compliant_NoClusterPermissions(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
		}},
	}
	result := CheckOperatorNoSCCAccess(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNoSCCAccess_Compliant_NoSCCRules(t *testing.T) {
	csv := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
	}
	csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions = []v1alpha1.StrategyDeploymentPermissions{{
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list"},
		}},
	}}
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv}}
	result := CheckOperatorNoSCCAccess(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNoSCCAccess_NonCompliant_SCCResource(t *testing.T) {
	csv := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
	}
	csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions = []v1alpha1.StrategyDeploymentPermissions{{
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"security.openshift.io"},
			Resources: []string{"securitycontextconstraints"},
			Verbs:     []string{"use"},
		}},
	}}
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv}}
	result := CheckOperatorNoSCCAccess(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNoSCCAccess_NonCompliant_WildcardGroup(t *testing.T) {
	csv := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
	}
	csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions = []v1alpha1.StrategyDeploymentPermissions{{
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"},
			Resources: []string{"securitycontextconstraints"},
			Verbs:     []string{"use"},
		}},
	}}
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv}}
	result := CheckOperatorNoSCCAccess(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckNoSCCAccess_NonCompliant_WildcardResource(t *testing.T) {
	csv := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
	}
	csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions = []v1alpha1.StrategyDeploymentPermissions{{
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"security.openshift.io"},
			Resources: []string{"*"},
			Verbs:     []string{"get"},
		}},
	}}
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv}}
	result := CheckOperatorNoSCCAccess(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- No SCC Access additional scenarios (from certsuite access_test.go) ---

func TestCheckNoSCCAccess_MultiplePermissions(t *testing.T) {
	csv := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
	}
	csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions = []v1alpha1.StrategyDeploymentPermissions{
		{
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get", "list"},
			}},
		},
		{
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"security.openshift.io"},
				Resources: []string{"securitycontextconstraints"},
				Verbs:     []string{"use"},
			}},
		},
	}
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv}}
	result := CheckOperatorNoSCCAccess(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant (second permission entry has SCC), got %s", result.ComplianceStatus)
	}
}

// --- Installed Via OLM ---

func TestCheckInstalledViaOLM_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "op1", Namespace: "ns1",
				Annotations: map[string]string{"olm.operatorNamespace": "ns1"},
			},
		}},
	}
	result := CheckOperatorInstalledViaOLM(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckInstalledViaOLM_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
		}},
	}
	result := CheckOperatorInstalledViaOLM(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- Semantic Versioning ---

func TestCheckSemanticVersioning_Compliant(t *testing.T) {
	csv := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1.v1.2.3", Namespace: "ns1"},
	}
	csv.Spec.Version.Major = 1
	csv.Spec.Version.Minor = 2
	csv.Spec.Version.Patch = 3
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv}}
	result := CheckOperatorSemanticVersioning(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSemanticVersioning_NonCompliant_EmptyVersion(t *testing.T) {
	csv := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
	}
	// Default version is 0.0.0 which is valid semver
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv}}
	result := CheckOperatorSemanticVersioning(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant (0.0.0 is valid semver), got %s", result.ComplianceStatus)
	}
}

// --- CRD Versioning ---

func TestCheckCrdVersioning_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "foos.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Versions: []apiextv1.CustomResourceDefinitionVersion{
					{Name: "v1"},
					{Name: "v1alpha1"},
					{Name: "v2beta1"},
				},
			},
		}},
	}
	result := CheckCrdVersioning(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckCrdVersioning_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "foos.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Versions: []apiextv1.CustomResourceDefinitionVersion{
					{Name: "1.0.0"},
				},
			},
		}},
	}
	result := CheckCrdVersioning(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckCrdVersioning_NoCRDs(t *testing.T) {
	result := CheckCrdVersioning(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- CRD OpenAPI Schema ---

func TestCheckCrdOpenAPISchema_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "foos.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Versions: []apiextv1.CustomResourceDefinitionVersion{{
					Name: "v1",
					Schema: &apiextv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextv1.JSONSchemaProps{
							Type: "object",
						},
					},
				}},
			},
		}},
	}
	result := CheckCrdOpenAPISchema(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckCrdOpenAPISchema_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: []apiextv1.CustomResourceDefinition{{
			ObjectMeta: metav1.ObjectMeta{Name: "foos.example.com"},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Versions: []apiextv1.CustomResourceDefinitionVersion{{
					Name: "v1",
				}},
			},
		}},
	}
	result := CheckCrdOpenAPISchema(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

// --- Single CRD Owner ---

func TestCheckSingleCrdOwner_Compliant(t *testing.T) {
	csv1 := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
	}
	csv1.Spec.CustomResourceDefinitions.Owned = []v1alpha1.CRDDescription{
		{Name: "foos.example.com"},
	}
	csv2 := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op2", Namespace: "ns1"},
	}
	csv2.Spec.CustomResourceDefinitions.Owned = []v1alpha1.CRDDescription{
		{Name: "bars.example.com"},
	}
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv1, csv2}}
	result := CheckSingleCrdOwner(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSingleCrdOwner_NonCompliant(t *testing.T) {
	csv1 := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
	}
	csv1.Spec.CustomResourceDefinitions.Owned = []v1alpha1.CRDDescription{
		{Name: "foos.example.com"},
	}
	csv2 := v1alpha1.ClusterServiceVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "op2", Namespace: "ns1"},
	}
	csv2.Spec.CustomResourceDefinitions.Owned = []v1alpha1.CRDDescription{
		{Name: "foos.example.com"},
	}
	resources := &checks.DiscoveredResources{CSVs: []v1alpha1.ClusterServiceVersion{csv1, csv2}}
	result := CheckSingleCrdOwner(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckSingleCrdOwner_NoCSVs(t *testing.T) {
	result := CheckSingleCrdOwner(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- Operator Pods No Hugepages ---

func TestCheckOperatorPodsNoHugepages_Compliant(t *testing.T) {
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
	result := CheckOperatorPodsNoHugepages(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckOperatorPodsNoHugepages_NonCompliant(t *testing.T) {
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
	result := CheckOperatorPodsNoHugepages(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckOperatorPodsNoHugepages_NoPods(t *testing.T) {
	result := CheckOperatorPodsNoHugepages(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- OLM Skip Range ---

func TestCheckOlmSkipRange_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "op1", Namespace: "ns1",
				Annotations: map[string]string{"olm.skipRange": ">=1.0.0 <2.0.0"},
			},
		}},
	}
	result := CheckOperatorOlmSkipRange(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckOlmSkipRange_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{{
			ObjectMeta: metav1.ObjectMeta{Name: "op1", Namespace: "ns1"},
		}},
	}
	result := CheckOperatorOlmSkipRange(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckOlmSkipRange_NoCSVs(t *testing.T) {
	result := CheckOperatorOlmSkipRange(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}

// --- isValidSemver helper ---

func TestIsValidSemver(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"1.2.3", true},
		{"0.0.0", true},
		{"v1.2.3", true},
		{"1.2.3-rc1", true},
		{"10.20.30", true},
		{"", false},
		{"1.2", false},
		{"abc", false},
		{"v1", false},
	}
	for _, tt := range tests {
		got := isValidSemver(tt.version)
		if got != tt.valid {
			t.Errorf("isValidSemver(%q) = %v, want %v", tt.version, got, tt.valid)
		}
	}
}

// --- k8s version regex ---

func TestK8sVersionRegex(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"v1", true},
		{"v1alpha1", true},
		{"v1beta1", true},
		{"v2beta2", true},
		{"v10alpha3", true},
		{"1.0.0", false},
		{"v0", false},
		{"alpha1", false},
		{"v1gamma1", false},
	}
	for _, tt := range tests {
		got := k8sVersionRegex.MatchString(tt.version)
		if got != tt.valid {
			t.Errorf("k8sVersionRegex(%q) = %v, want %v", tt.version, got, tt.valid)
		}
	}
}

// --- Multiple same operators ---

func TestCheckMultipleSameOperators_Compliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "op-a.v1.0.0", Namespace: "ns1"},
				Spec:       v1alpha1.ClusterServiceVersionSpec{Version: makeVersion("1.0.0")},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "op-b.v2.0.0", Namespace: "ns1"},
				Spec:       v1alpha1.ClusterServiceVersionSpec{Version: makeVersion("2.0.0")},
			},
		},
	}
	result := CheckMultipleSameOperators(resources)
	if result.ComplianceStatus != "Compliant" {
		t.Errorf("expected Compliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckMultipleSameOperators_NonCompliant(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CSVs: []v1alpha1.ClusterServiceVersion{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "my-operator.v1.0.0", Namespace: "ns1"},
				Spec:       v1alpha1.ClusterServiceVersionSpec{Version: makeVersion("1.0.0")},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "my-operator.v2.0.0", Namespace: "ns2"},
				Spec:       v1alpha1.ClusterServiceVersionSpec{Version: makeVersion("2.0.0")},
			},
		},
	}
	result := CheckMultipleSameOperators(resources)
	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("expected NonCompliant, got %s", result.ComplianceStatus)
	}
}

func TestCheckMultipleSameOperators_Skipped(t *testing.T) {
	result := CheckMultipleSameOperators(&checks.DiscoveredResources{})
	if result.ComplianceStatus != "Skipped" {
		t.Errorf("expected Skipped, got %s", result.ComplianceStatus)
	}
}
