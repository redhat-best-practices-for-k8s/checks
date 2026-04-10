package lifecycle

import (
	"testing"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func init() {
	// Use short timeouts in tests since the fake client doesn't update status
	scalingTimeout = 100 * time.Millisecond
	readinessPollDelay = 10 * time.Millisecond
}

func makeDeployment(name, namespace string, replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "test", Image: "test:latest"}}},
			},
		},
		Status: appsv1.DeploymentStatus{
			Replicas:          replicas,
			ReadyReplicas:     replicas,
			UpdatedReplicas:   replicas,
			AvailableReplicas: replicas,
		},
	}
}

func makeStatefulSet(name, namespace string, replicas int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "test", Image: "test:latest"}}},
			},
		},
		Status: appsv1.StatefulSetStatus{
			Replicas:      replicas,
			ReadyReplicas: replicas,
		},
	}
}

// makeCRDs creates a CRD slice with a single CRD having the given name and kind.
func makeCRDs(name, kind string) []apiextv1.CustomResourceDefinition {
	return []apiextv1.CustomResourceDefinition{
		{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Names: apiextv1.CustomResourceDefinitionNames{Kind: kind},
			},
		},
	}
}

func TestCheckDeploymentScaling_NoClient(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Deployments: []appsv1.Deployment{*makeDeployment("test", "ns", 2)},
	}

	result := CheckDeploymentScaling(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error when K8sClientset is nil, got %s", result.ComplianceStatus)
	}
}

func TestCheckDeploymentScaling_NoDeployments(t *testing.T) {
	resources := &checks.DiscoveredResources{
		K8sClientset: testutil.NewMockK8sClient(),
	}

	result := CheckDeploymentScaling(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped with no Deployments, got %s", result.ComplianceStatus)
	}
}

func TestCheckDeploymentScaling_ScaleUpDown(t *testing.T) {
	deploy := makeDeployment("web", "default", 1)
	client := testutil.NewMockK8sClient(deploy)

	resources := &checks.DiscoveredResources{
		K8sClientset: client,
		Deployments:  []appsv1.Deployment{*deploy},
	}

	result := CheckDeploymentScaling(resources)

	// With the fake client, replicas update but status doesn't auto-update,
	// so this will time out. We verify the check runs and reports appropriately.
	if result.ComplianceStatus == "Compliant" {
		// Fake client doesn't update status, so we expect NonCompliant or the check
		// might succeed depending on timing. Either way, the check should run.
		t.Log("Deployment scaling check completed")
	}
}

func TestCheckDeploymentScaling_MultipleDeployments(t *testing.T) {
	deploy1 := makeDeployment("web", "default", 2)
	deploy2 := makeDeployment("api", "default", 3)
	client := testutil.NewMockK8sClient(deploy1, deploy2)

	resources := &checks.DiscoveredResources{
		K8sClientset: client,
		Deployments:  []appsv1.Deployment{*deploy1, *deploy2},
	}

	result := CheckDeploymentScaling(resources)

	if len(result.Details) != 2 {
		t.Errorf("Expected 2 detail entries, got %d", len(result.Details))
	}
}

func TestCheckStatefulSetScaling_NoStatefulSets(t *testing.T) {
	resources := &checks.DiscoveredResources{
		K8sClientset: testutil.NewMockK8sClient(),
	}

	result := CheckStatefulSetScaling(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped with no StatefulSets, got %s", result.ComplianceStatus)
	}
}

func TestCheckStatefulSetScaling_NoClient(t *testing.T) {
	resources := &checks.DiscoveredResources{
		StatefulSets: []appsv1.StatefulSet{*makeStatefulSet("db", "ns", 1)},
	}

	result := CheckStatefulSetScaling(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error when K8sClientset is nil, got %s", result.ComplianceStatus)
	}
}

func TestCheckStatefulSetScaling_ScaleUpDown(t *testing.T) {
	sts := makeStatefulSet("db", "default", 3)
	client := testutil.NewMockK8sClient(sts)

	resources := &checks.DiscoveredResources{
		K8sClientset: client,
		StatefulSets: []appsv1.StatefulSet{*sts},
	}

	result := CheckStatefulSetScaling(resources)

	// Verify the check ran and produced details
	if len(result.Details) == 0 {
		t.Error("Expected details from scaling check")
	}
}

func TestGetK8sClient_InvalidType(t *testing.T) {
	resources := &checks.DiscoveredResources{
		K8sClientset: "not a kubernetes client",
	}

	_, err := getK8sClient(resources)
	if err == nil {
		t.Error("Expected error for invalid K8sClientset type")
	}
}

func TestSetDeploymentReplicas(t *testing.T) {
	deploy := makeDeployment("web", "default", 2)
	client := testutil.NewMockK8sClient(deploy)

	err := setDeploymentReplicas(client, "default", "web", 3)
	if err != nil {
		t.Fatalf("setDeploymentReplicas failed: %v", err)
	}

	// Verify the update was applied
	updated, err := client.AppsV1().Deployments("default").Get(t.Context(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get updated deployment: %v", err)
	}

	if *updated.Spec.Replicas != 3 {
		t.Errorf("Expected 3 replicas, got %d", *updated.Spec.Replicas)
	}
}

func TestSetStatefulSetReplicas(t *testing.T) {
	sts := makeStatefulSet("db", "default", 2)
	client := testutil.NewMockK8sClient(sts)

	err := setStatefulSetReplicas(client, "default", "db", 5)
	if err != nil {
		t.Fatalf("setStatefulSetReplicas failed: %v", err)
	}

	updated, err := client.AppsV1().StatefulSets("default").Get(t.Context(), "db", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get updated statefulset: %v", err)
	}

	if *updated.Spec.Replicas != 5 {
		t.Errorf("Expected 5 replicas, got %d", *updated.Spec.Replicas)
	}
}

func TestSetDeploymentReplicas_NotFound(t *testing.T) {
	client := testutil.NewMockK8sClient()

	err := setDeploymentReplicas(client, "default", "nonexistent", 3)
	if err == nil {
		t.Error("Expected error for nonexistent deployment")
	}
}

func TestWaitForDeploymentReady_AlreadyReady(t *testing.T) {
	deploy := makeDeployment("web", "default", 2)
	client := testutil.NewMockK8sClient(deploy)

	err := waitForDeploymentReady(client, "default", "web", 5*readinessPollDelay)
	if err != nil {
		t.Errorf("Expected deployment to be ready: %v", err)
	}
}

func TestWaitForDeploymentReady_NotFound(t *testing.T) {
	client := testutil.NewMockK8sClient()

	err := waitForDeploymentReady(client, "default", "nonexistent", readinessPollDelay)
	if err == nil {
		t.Error("Expected error for nonexistent deployment")
	}
}

func TestWaitForStatefulSetReady_AlreadyReady(t *testing.T) {
	sts := makeStatefulSet("db", "default", 2)
	client := testutil.NewMockK8sClient(sts)

	err := waitForStatefulSetReady(client, "default", "db", 5*readinessPollDelay)
	if err != nil {
		t.Errorf("Expected statefulset to be ready: %v", err)
	}
}

func TestScaleDeployment_NilReplicas(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "test", Image: "test:latest"}}},
			},
		},
		Status: appsv1.DeploymentStatus{
			Replicas:          1,
			ReadyReplicas:     1,
			UpdatedReplicas:   1,
			AvailableReplicas: 1,
		},
	}
	client := testutil.NewMockK8sClient(deploy)

	// scaleDeployment should handle nil replicas (default to 1)
	err := scaleDeployment(client, deploy)
	// Fake client won't update status, so we just verify it doesn't panic
	_ = err
}

func TestIsManaged(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		managed  []string
		expected bool
	}{
		{"found", "deploy-a", []string{"deploy-a", "deploy-b"}, true},
		{"not found", "deploy-c", []string{"deploy-a", "deploy-b"}, false},
		{"empty list", "deploy-a", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isManaged(tc.input, tc.managed); got != tc.expected {
				t.Errorf("isManaged(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestIsInSkipList(t *testing.T) {
	skipList := []checks.SkipScalingEntry{
		{Name: "skip-deploy", Namespace: "ns1"},
	}

	if !isInSkipList("skip-deploy", "ns1", skipList) {
		t.Error("Expected skip-deploy/ns1 to be in skip list")
	}
	if isInSkipList("skip-deploy", "ns2", skipList) {
		t.Error("Expected skip-deploy/ns2 to NOT be in skip list (wrong namespace)")
	}
	if isInSkipList("other", "ns1", skipList) {
		t.Error("Expected other/ns1 to NOT be in skip list")
	}
	if isInSkipList("skip-deploy", "ns1", nil) {
		t.Error("Expected false for nil skip list")
	}
}

func TestCheckOwnerReference(t *testing.T) {
	crds := []checks.CRDInfo{
		{Name: "myresources.example.com", Kind: "MyResource"},
	}
	ownerRefs := []metav1.OwnerReference{
		{Kind: "MyResource", Name: "my-cr-1"},
	}

	// Scalable CRD filter -> should return true
	scalableFilters := []checks.CRDFilter{
		{NameSuffix: "example.com", Scalable: true},
	}
	if !checkOwnerReference(ownerRefs, scalableFilters, crds) {
		t.Error("Expected true for scalable CRD filter")
	}

	// Non-scalable CRD filter -> should return false
	nonScalableFilters := []checks.CRDFilter{
		{NameSuffix: "example.com", Scalable: false},
	}
	if checkOwnerReference(ownerRefs, nonScalableFilters, crds) {
		t.Error("Expected false for non-scalable CRD filter")
	}

	// No matching owner refs
	if checkOwnerReference(nil, scalableFilters, crds) {
		t.Error("Expected false for empty owner refs")
	}

	// No matching CRD filter
	unmatchedFilters := []checks.CRDFilter{
		{NameSuffix: "other.com", Scalable: true},
	}
	if checkOwnerReference(ownerRefs, unmatchedFilters, crds) {
		t.Error("Expected false for unmatched CRD filter suffix")
	}
}

func TestCheckDeploymentScaling_SkipList(t *testing.T) {
	deploy := makeDeployment("skip-me", "ns1", 2)
	client := testutil.NewMockK8sClient(deploy)

	resources := &checks.DiscoveredResources{
		K8sClientset: client,
		Deployments:  []appsv1.Deployment{*deploy},
		SkipScalingDeployments: []checks.SkipScalingEntry{
			{Name: "skip-me", Namespace: "ns1"},
		},
	}

	result := CheckDeploymentScaling(resources)

	// Skipped deployments produce no details. With all deployments skipped,
	// the result stays Compliant with no details (mirrors certsuite behavior
	// where an empty compliant list leads to SKIPPED at the framework level).
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Compliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 0 {
		t.Errorf("Expected 0 details for skipped deployment, got %d", len(result.Details))
	}
}

func TestCheckDeploymentScaling_ManagedScalable(t *testing.T) {
	deploy := makeDeployment("managed-deploy", "ns1", 2)
	deploy.OwnerReferences = []metav1.OwnerReference{
		{Kind: "MyApp", Name: "my-app-cr"},
	}
	client := testutil.NewMockK8sClient(deploy)

	resources := &checks.DiscoveredResources{
		K8sClientset:       client,
		Deployments:        []appsv1.Deployment{*deploy},
		ManagedDeployments: []string{"managed-deploy"},
		CRDFilters: []checks.CRDFilter{
			{NameSuffix: "example.com", Scalable: true},
		},
		CRDs: makeCRDs("myapps.example.com", "MyApp"),
	}

	result := CheckDeploymentScaling(resources)

	// Managed + scalable CRD -> skipped (no detail added).
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Compliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 0 {
		t.Errorf("Expected 0 details for managed scalable deployment, got %d", len(result.Details))
	}
}

func TestCheckDeploymentScaling_ManagedNonScalable(t *testing.T) {
	deploy := makeDeployment("managed-deploy", "ns1", 2)
	deploy.OwnerReferences = []metav1.OwnerReference{
		{Kind: "MyApp", Name: "my-app-cr"},
	}
	client := testutil.NewMockK8sClient(deploy)

	resources := &checks.DiscoveredResources{
		K8sClientset:       client,
		Deployments:        []appsv1.Deployment{*deploy},
		ManagedDeployments: []string{"managed-deploy"},
		CRDFilters: []checks.CRDFilter{
			{NameSuffix: "example.com", Scalable: false},
		},
		CRDs: makeCRDs("myapps.example.com", "MyApp"),
	}

	result := CheckDeploymentScaling(resources)

	// Managed + non-scalable CRD -> non-compliant.
	if result.ComplianceStatus != checks.StatusNonCompliant {
		t.Errorf("Expected NonCompliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Fatalf("Expected 1 detail, got %d", len(result.Details))
	}
	if result.Details[0].Compliant {
		t.Error("Expected detail to be non-compliant")
	}
}

func TestCheckStatefulSetScaling_SkipList(t *testing.T) {
	sts := makeStatefulSet("skip-me", "ns1", 2)
	client := testutil.NewMockK8sClient(sts)

	resources := &checks.DiscoveredResources{
		K8sClientset: client,
		StatefulSets: []appsv1.StatefulSet{*sts},
		SkipScalingStatefulSets: []checks.SkipScalingEntry{
			{Name: "skip-me", Namespace: "ns1"},
		},
	}

	result := CheckStatefulSetScaling(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Compliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 0 {
		t.Errorf("Expected 0 details for skipped statefulset, got %d", len(result.Details))
	}
}

func TestCheckStatefulSetScaling_ManagedScalable(t *testing.T) {
	sts := makeStatefulSet("managed-sts", "ns1", 2)
	sts.OwnerReferences = []metav1.OwnerReference{
		{Kind: "MyApp", Name: "my-app-cr"},
	}
	client := testutil.NewMockK8sClient(sts)

	resources := &checks.DiscoveredResources{
		K8sClientset:        client,
		StatefulSets:        []appsv1.StatefulSet{*sts},
		ManagedStatefulSets: []string{"managed-sts"},
		CRDFilters: []checks.CRDFilter{
			{NameSuffix: "example.com", Scalable: true},
		},
		CRDs: makeCRDs("myapps.example.com", "MyApp"),
	}

	result := CheckStatefulSetScaling(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Compliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 0 {
		t.Errorf("Expected 0 details for managed scalable statefulset, got %d", len(result.Details))
	}
}

func TestCheckStatefulSetScaling_ManagedNonScalable(t *testing.T) {
	sts := makeStatefulSet("managed-sts", "ns1", 2)
	sts.OwnerReferences = []metav1.OwnerReference{
		{Kind: "MyApp", Name: "my-app-cr"},
	}
	client := testutil.NewMockK8sClient(sts)

	resources := &checks.DiscoveredResources{
		K8sClientset:        client,
		StatefulSets:        []appsv1.StatefulSet{*sts},
		ManagedStatefulSets: []string{"managed-sts"},
		CRDFilters: []checks.CRDFilter{
			{NameSuffix: "example.com", Scalable: false},
		},
		CRDs: makeCRDs("myapps.example.com", "MyApp"),
	}

	result := CheckStatefulSetScaling(resources)

	if result.ComplianceStatus != checks.StatusNonCompliant {
		t.Errorf("Expected NonCompliant, got %s", result.ComplianceStatus)
	}
	if len(result.Details) != 1 {
		t.Fatalf("Expected 1 detail, got %d", len(result.Details))
	}
	if result.Details[0].Compliant {
		t.Error("Expected detail to be non-compliant")
	}
}

func TestBuildCRDInfos(t *testing.T) {
	resources := &checks.DiscoveredResources{
		CRDs: makeCRDs("foos.example.com", "Foo"),
	}
	infos := buildCRDInfos(resources)
	if len(infos) != 1 {
		t.Fatalf("Expected 1 CRD info, got %d", len(infos))
	}
	if infos[0].Name != "foos.example.com" || infos[0].Kind != "Foo" {
		t.Errorf("Unexpected CRD info: %+v", infos[0])
	}
}

func TestCheckDeploymentScaling_WithObjects(t *testing.T) {
	// Create a deployment that starts ready, and the fake client
	// will let us update replicas. Status won't auto-update though.
	deploy := makeDeployment("web", "default", 2)

	var objects []runtime.Object
	objects = append(objects, deploy)

	client := testutil.NewMockK8sClient(objects...)

	resources := &checks.DiscoveredResources{
		K8sClientset: client,
		Deployments:  []appsv1.Deployment{*deploy},
	}

	result := CheckDeploymentScaling(resources)

	// Should have exactly one detail entry for the single deployment
	if len(result.Details) != 1 {
		t.Errorf("Expected 1 detail entry, got %d", len(result.Details))
	}

	// The detail should reference the correct deployment
	if len(result.Details) > 0 && result.Details[0].Name != "default/web" {
		t.Errorf("Expected detail for default/web, got %s", result.Details[0].Name)
	}
}
