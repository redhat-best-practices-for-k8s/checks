package lifecycle

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/redhat-best-practices-for-k8s/checks"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	scaleclient "k8s.io/client-go/scale"
)

// mockScalesGetter implements scale.ScalesGetter for testing.
type mockScalesGetter struct {
	scales map[string]*autoscalingv1.Scale // key: "namespace/group.resource/name"
	mu     sync.Mutex
}

var _ scaleclient.ScalesGetter = (*mockScalesGetter)(nil)

func newMockScalesGetter() *mockScalesGetter {
	return &mockScalesGetter{
		scales: make(map[string]*autoscalingv1.Scale),
	}
}

func scaleKey(namespace string, gr schema.GroupResource, name string) string {
	return fmt.Sprintf("%s/%s.%s/%s", namespace, gr.Resource, gr.Group, name)
}

func (m *mockScalesGetter) addScale(namespace, name string, gr schema.GroupResource, replicas int32) {
	key := scaleKey(namespace, gr, name)
	m.scales[key] = &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       autoscalingv1.ScaleSpec{Replicas: replicas},
		Status:     autoscalingv1.ScaleStatus{Replicas: replicas},
	}
}

func (m *mockScalesGetter) Scales(namespace string) scaleclient.ScaleInterface {
	return &mockScaleInterface{getter: m, namespace: namespace}
}

// mockScaleInterface implements scale.ScaleInterface for testing.
type mockScaleInterface struct {
	getter    *mockScalesGetter
	namespace string
}

var _ scaleclient.ScaleInterface = (*mockScaleInterface)(nil)

func (m *mockScaleInterface) Get(_ context.Context, resource schema.GroupResource, name string, _ metav1.GetOptions) (*autoscalingv1.Scale, error) {
	m.getter.mu.Lock()
	defer m.getter.mu.Unlock()

	key := scaleKey(m.namespace, resource, name)
	s, ok := m.getter.scales[key]
	if !ok {
		return nil, fmt.Errorf("scale not found: %s", key)
	}
	return s.DeepCopy(), nil
}

func (m *mockScaleInterface) Update(_ context.Context, resource schema.GroupResource, scaleObj *autoscalingv1.Scale, _ metav1.UpdateOptions) (*autoscalingv1.Scale, error) {
	m.getter.mu.Lock()
	defer m.getter.mu.Unlock()

	key := scaleKey(m.namespace, resource, scaleObj.Name)
	if _, ok := m.getter.scales[key]; !ok {
		return nil, fmt.Errorf("scale not found: %s", key)
	}
	// Update both spec and status (mock simulates controller reconciliation)
	m.getter.scales[key].Spec.Replicas = scaleObj.Spec.Replicas
	m.getter.scales[key].Status.Replicas = scaleObj.Spec.Replicas
	return m.getter.scales[key].DeepCopy(), nil
}

func (m *mockScaleInterface) Patch(_ context.Context, _ schema.GroupVersionResource, _ string, _ types.PatchType, _ []byte, _ metav1.PatchOptions) (*autoscalingv1.Scale, error) {
	return nil, fmt.Errorf("patch not implemented in mock")
}

func TestCheckCRDScaling_NoScaleClient(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ScalableResources: []checks.ScalableResource{
			{Name: "my-cr", Namespace: "ns", Replicas: 2, GroupResource: schema.GroupResource{Group: "example.com", Resource: "myresources"}},
		},
	}

	result := CheckCRDScaling(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckCRDScaling_InvalidScaleClient(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ScaleClient: "not a scale client",
		ScalableResources: []checks.ScalableResource{
			{Name: "my-cr", Namespace: "ns", Replicas: 2, GroupResource: schema.GroupResource{Group: "example.com", Resource: "myresources"}},
		},
	}

	result := CheckCRDScaling(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckCRDScaling_NoScalableResources(t *testing.T) {
	mock := newMockScalesGetter()
	resources := &checks.DiscoveredResources{
		ScaleClient: mock,
	}

	result := CheckCRDScaling(resources)

	if result.ComplianceStatus != "Skipped" {
		t.Errorf("Expected Skipped, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckCRDScaling_Compliant_ScaleDown(t *testing.T) {
	gr := schema.GroupResource{Group: "example.com", Resource: "myresources"}
	mock := newMockScalesGetter()
	mock.addScale("ns", "my-cr", gr, 3)

	resources := &checks.DiscoveredResources{
		ScaleClient: mock,
		ScalableResources: []checks.ScalableResource{
			{Name: "my-cr", Namespace: "ns", Replicas: 3, GroupResource: gr},
		},
	}

	result := CheckCRDScaling(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
	if len(result.Details) != 1 {
		t.Fatalf("Expected 1 detail, got %d", len(result.Details))
	}
	if !result.Details[0].Compliant {
		t.Errorf("Expected detail to be compliant: %s", result.Details[0].Message)
	}
}

func TestCheckCRDScaling_Compliant_ScaleUp(t *testing.T) {
	gr := schema.GroupResource{Group: "apps.example.com", Resource: "webapps"}
	mock := newMockScalesGetter()
	mock.addScale("default", "webapp", gr, 1)

	resources := &checks.DiscoveredResources{
		ScaleClient: mock,
		ScalableResources: []checks.ScalableResource{
			{Name: "webapp", Namespace: "default", Replicas: 1, GroupResource: gr},
		},
	}

	result := CheckCRDScaling(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckCRDScaling_NonCompliant_NotFound(t *testing.T) {
	gr := schema.GroupResource{Group: "example.com", Resource: "myresources"}
	mock := newMockScalesGetter()
	// Don't add the scale object — it won't be found

	resources := &checks.DiscoveredResources{
		ScaleClient: mock,
		ScalableResources: []checks.ScalableResource{
			{Name: "missing-cr", Namespace: "ns", Replicas: 2, GroupResource: gr},
		},
	}

	result := CheckCRDScaling(resources)

	if result.ComplianceStatus != "NonCompliant" {
		t.Errorf("Expected NonCompliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckCRDScaling_MultipleResources(t *testing.T) {
	gr1 := schema.GroupResource{Group: "example.com", Resource: "foos"}
	gr2 := schema.GroupResource{Group: "example.com", Resource: "bars"}
	mock := newMockScalesGetter()
	mock.addScale("ns", "foo-1", gr1, 2)
	mock.addScale("ns", "bar-1", gr2, 1)

	resources := &checks.DiscoveredResources{
		ScaleClient: mock,
		ScalableResources: []checks.ScalableResource{
			{Name: "foo-1", Namespace: "ns", Replicas: 2, GroupResource: gr1},
			{Name: "bar-1", Namespace: "ns", Replicas: 1, GroupResource: gr2},
		},
	}

	result := CheckCRDScaling(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant, got %s: %s", result.ComplianceStatus, result.Reason)
	}
	if len(result.Details) != 2 {
		t.Errorf("Expected 2 details, got %d", len(result.Details))
	}
}

func TestSetCRDReplicas(t *testing.T) {
	gr := schema.GroupResource{Group: "example.com", Resource: "myresources"}
	mock := newMockScalesGetter()
	mock.addScale("ns", "my-cr", gr, 2)

	err := setCRDReplicas(mock, "ns", "my-cr", gr, 5)
	if err != nil {
		t.Fatalf("setCRDReplicas failed: %v", err)
	}

	s, _ := mock.Scales("ns").Get(context.Background(), gr, "my-cr", metav1.GetOptions{})
	if s.Spec.Replicas != 5 {
		t.Errorf("Expected 5 replicas, got %d", s.Spec.Replicas)
	}
}

func TestSetCRDReplicas_NotFound(t *testing.T) {
	gr := schema.GroupResource{Group: "example.com", Resource: "myresources"}
	mock := newMockScalesGetter()

	err := setCRDReplicas(mock, "ns", "nonexistent", gr, 3)
	if err == nil {
		t.Error("Expected error for nonexistent resource")
	}
}

func TestWaitForCRDScaleReady_AlreadyReady(t *testing.T) {
	gr := schema.GroupResource{Group: "example.com", Resource: "myresources"}
	mock := newMockScalesGetter()
	mock.addScale("ns", "my-cr", gr, 3)

	err := waitForCRDScaleReady(mock, "ns", "my-cr", gr, 3, 5*readinessPollDelay)
	if err != nil {
		t.Errorf("Expected ready: %v", err)
	}
}

func TestWaitForCRDScaleReady_Timeout(t *testing.T) {
	gr := schema.GroupResource{Group: "example.com", Resource: "myresources"}
	mock := newMockScalesGetter()
	mock.addScale("ns", "my-cr", gr, 2)

	err := waitForCRDScaleReady(mock, "ns", "my-cr", gr, 5, readinessPollDelay)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestCheckCRDScaling_ZeroReplicas(t *testing.T) {
	gr := schema.GroupResource{Group: "example.com", Resource: "myresources"}
	mock := newMockScalesGetter()
	mock.addScale("ns", "my-cr", gr, 0)

	resources := &checks.DiscoveredResources{
		ScaleClient: mock,
		ScalableResources: []checks.ScalableResource{
			{Name: "my-cr", Namespace: "ns", Replicas: 0, GroupResource: gr},
		},
	}

	result := CheckCRDScaling(resources)

	if result.ComplianceStatus != "Compliant" {
		t.Errorf("Expected Compliant with 0 replicas, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}
