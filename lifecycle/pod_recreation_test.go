package lifecycle

import (
	"testing"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	"github.com/redhat-best-practices-for-k8s/checks/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	// Use short timeouts in tests since the fake client doesn't update status
	podRecreationBaseTimeout = 100 * time.Millisecond
	podRecreationPerPodExtra = 10 * time.Millisecond
	podDeletionGracePeriod = 0
}

func makePodOnNode(name, namespace, nodeName, ownerKind, ownerName string) corev1.Pod {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{
				{Kind: ownerKind, Name: ownerName},
			},
		},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{{Name: "test", Image: "test:latest"}},
		},
	}

	if ownerKind == "ReplicaSet" {
		pod.Labels = map[string]string{"pod-template-hash": "abc123"}
	}

	return pod
}

func TestCheckPodRecreation_NoClient(t *testing.T) {
	resources := &checks.DiscoveredResources{
		Pods: []corev1.Pod{makePodOnNode("p1", "ns", "node1", "ReplicaSet", "web-abc123")},
	}

	result := CheckPodRecreation(resources)

	if result.ComplianceStatus != "Error" {
		t.Errorf("Expected Error, got %s", result.ComplianceStatus)
	}
}

func TestCheckPodRecreation_NoPods(t *testing.T) {
	resources := &checks.DiscoveredResources{
		K8sClientset: testutil.NewMockK8sClient(),
	}

	result := CheckPodRecreation(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped with no pods, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckPodRecreation_NoDaemonSetOnly(t *testing.T) {
	resources := &checks.DiscoveredResources{
		K8sClientset: testutil.NewMockK8sClient(),
		Pods: []corev1.Pod{
			makePodOnNode("ds-pod", "ns", "node1", "DaemonSet", "my-ds"),
		},
	}

	result := CheckPodRecreation(resources)

	// DaemonSet pods don't have ReplicaSet/StatefulSet owners, so no target nodes
	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped with only DaemonSet pods, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckPodRecreation_AllNodesUnsafe_ScannerPod(t *testing.T) {
	resources := &checks.DiscoveredResources{
		K8sClientset: testutil.NewMockK8sClient(),
		Pods: []corev1.Pod{
			makePodOnNode("web-pod", "ns", "node1", "ReplicaSet", "web-abc123"),
		},
		ScannerPodNodeName: "node1", // Scanner on same node
	}

	result := CheckPodRecreation(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped when scanner is on target node, got %s: %s", result.ComplianceStatus, result.Reason)
	}
	if result.Reason != "All target nodes host scanner or probe pods; cannot safely cordon" {
		t.Errorf("Unexpected reason: %s", result.Reason)
	}
}

func TestCheckPodRecreation_AllNodesUnsafe_ProbePod(t *testing.T) {
	probePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "probe", Namespace: "certsuite"},
		Spec:       corev1.PodSpec{NodeName: "node1"},
	}

	resources := &checks.DiscoveredResources{
		K8sClientset: testutil.NewMockK8sClient(),
		Pods: []corev1.Pod{
			makePodOnNode("web-pod", "ns", "node1", "ReplicaSet", "web-abc123"),
		},
		ProbePods: map[string]*corev1.Pod{"node1": probePod},
	}

	result := CheckPodRecreation(resources)

	if result.ComplianceStatus != checks.StatusCompliant {
		t.Errorf("Expected Skipped when probe is on target node, got %s: %s", result.ComplianceStatus, result.Reason)
	}
}

func TestCheckPodRecreation_SafeNodeAvailable(t *testing.T) {
	// Pod on node2 is safe; scanner is on node1
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node2"},
	}
	pod := makePodOnNode("web-pod", "ns", "node2", "ReplicaSet", "web-abc123")

	client := testutil.NewMockK8sClient(node, &pod)

	resources := &checks.DiscoveredResources{
		K8sClientset:       client,
		Pods:               []corev1.Pod{pod},
		ScannerPodNodeName: "node1",
	}

	result := CheckPodRecreation(resources)

	// The check should run (not skip). It may fail due to fake client limitations
	// but shouldn't be Skipped.
	if result.ComplianceStatus == checks.StatusCompliant {
		t.Errorf("Expected check to run on safe node, got Skipped: %s", result.Reason)
	}
}

func TestGetUnsafeNodes(t *testing.T) {
	probePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "probe", Namespace: "certsuite"},
	}

	resources := &checks.DiscoveredResources{
		ScannerPodNodeName: "control-plane-1",
		ProbePods: map[string]*corev1.Pod{
			"worker-1": probePod,
			"worker-2": probePod,
		},
	}

	unsafe := getUnsafeNodes(resources)

	if !unsafe["control-plane-1"] {
		t.Error("Expected control-plane-1 to be unsafe (scanner pod)")
	}
	if !unsafe["worker-1"] {
		t.Error("Expected worker-1 to be unsafe (probe pod)")
	}
	if !unsafe["worker-2"] {
		t.Error("Expected worker-2 to be unsafe (probe pod)")
	}
	if unsafe["worker-3"] {
		t.Error("Expected worker-3 to be safe")
	}
}

func TestGetUnsafeNodes_NoScannerPod(t *testing.T) {
	resources := &checks.DiscoveredResources{
		ScannerPodNodeName: "",
	}

	unsafe := getUnsafeNodes(resources)

	if len(unsafe) != 0 {
		t.Errorf("Expected no unsafe nodes when scanner runs externally, got %d", len(unsafe))
	}
}

func TestGetTargetNodes(t *testing.T) {
	pods := []corev1.Pod{
		makePodOnNode("web-1", "ns", "node1", "ReplicaSet", "web-abc123"),
		makePodOnNode("web-2", "ns", "node2", "ReplicaSet", "web-abc123"),
		makePodOnNode("ds-pod", "ns", "node3", "DaemonSet", "my-ds"),
		makePodOnNode("bare-pod", "ns", "node4", "Job", "my-job"),
	}

	nodes := getTargetNodes(pods)

	nodeSet := make(map[string]bool)
	for _, n := range nodes {
		nodeSet[n] = true
	}

	if !nodeSet["node1"] || !nodeSet["node2"] {
		t.Error("Expected node1 and node2 as target nodes (ReplicaSet pods)")
	}
	if nodeSet["node3"] {
		t.Error("node3 should not be a target (DaemonSet pod)")
	}
	if nodeSet["node4"] {
		t.Error("node4 should not be a target (Job pod)")
	}
}

func TestGetTargetNodes_StatefulSet(t *testing.T) {
	pods := []corev1.Pod{
		makePodOnNode("db-0", "ns", "node5", "StatefulSet", "db"),
	}

	nodes := getTargetNodes(pods)

	if len(nodes) != 1 || nodes[0] != "node5" {
		t.Errorf("Expected [node5], got %v", nodes)
	}
}

func TestGetManagedPodsOnNode(t *testing.T) {
	pods := []corev1.Pod{
		makePodOnNode("web-1", "ns", "node1", "ReplicaSet", "web-abc123"),
		makePodOnNode("ds-pod", "ns", "node1", "DaemonSet", "my-ds"),
		makePodOnNode("web-2", "ns", "node2", "ReplicaSet", "web-xyz789"),
		makePodOnNode("db-0", "ns", "node1", "StatefulSet", "db"),
	}

	managed := getManagedPodsOnNode(pods, "node1")

	if len(managed) != 2 {
		t.Errorf("Expected 2 managed pods on node1, got %d", len(managed))
	}

	names := make(map[string]bool)
	for _, p := range managed {
		names[p.Name] = true
	}
	if !names["web-1"] || !names["db-0"] {
		t.Errorf("Expected web-1 and db-0, got %v", names)
	}
}

func TestIsDaemonSetPod(t *testing.T) {
	dsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "DaemonSet", Name: "my-ds"},
			},
		},
	}

	rsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "web-abc123"},
			},
		},
	}

	if !isDaemonSetPod(dsPod) {
		t.Error("Expected DaemonSet pod to be identified as DaemonSet")
	}
	if isDaemonSetPod(rsPod) {
		t.Error("Expected ReplicaSet pod to not be identified as DaemonSet")
	}
}

func TestDeploymentNameFromReplicaSet(t *testing.T) {
	tests := []struct {
		rsName   string
		hash     string
		expected string
	}{
		{"web-abc123", "abc123", "web"},
		{"my-app-name-xyz789", "xyz789", "my-app-name"},
		{"nohash", "", "nohash"},
	}

	for _, tt := range tests {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{"pod-template-hash": tt.hash},
			},
		}

		got := deploymentNameFromReplicaSet(tt.rsName, pod)
		if got != tt.expected {
			t.Errorf("deploymentNameFromReplicaSet(%q, hash=%q) = %q, want %q",
				tt.rsName, tt.hash, got, tt.expected)
		}
	}
}

func TestGetOwnerSets(t *testing.T) {
	pods := []corev1.Pod{
		makePodOnNode("web-1", "ns", "node1", "ReplicaSet", "web-abc123"),
		makePodOnNode("web-2", "ns", "node1", "ReplicaSet", "web-abc123"),
		makePodOnNode("db-0", "ns", "node1", "StatefulSet", "db"),
	}

	owners := getOwnerSets(pods)

	if len(owners) != 2 {
		t.Fatalf("Expected 2 unique owners, got %d", len(owners))
	}

	ownerMap := make(map[string]string)
	for _, o := range owners {
		ownerMap[o.name] = o.kind
	}

	if ownerMap["web"] != "Deployment" {
		t.Error("Expected 'web' Deployment owner")
	}
	if ownerMap["db"] != "StatefulSet" {
		t.Error("Expected 'db' StatefulSet owner")
	}
}

func TestSetNodeUnschedulable(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec:       corev1.NodeSpec{Unschedulable: false},
	}

	client := testutil.NewMockK8sClient(node)

	// Cordon
	err := setNodeUnschedulable(client, "worker-1", true)
	if err != nil {
		t.Fatalf("Failed to cordon: %v", err)
	}

	updated, _ := client.CoreV1().Nodes().Get(t.Context(), "worker-1", metav1.GetOptions{})
	if !updated.Spec.Unschedulable {
		t.Error("Expected node to be unschedulable after cordon")
	}

	// Uncordon
	err = setNodeUnschedulable(client, "worker-1", false)
	if err != nil {
		t.Fatalf("Failed to uncordon: %v", err)
	}

	updated, _ = client.CoreV1().Nodes().Get(t.Context(), "worker-1", metav1.GetOptions{})
	if updated.Spec.Unschedulable {
		t.Error("Expected node to be schedulable after uncordon")
	}
}

func TestSetNodeUnschedulable_NotFound(t *testing.T) {
	client := testutil.NewMockK8sClient()

	err := setNodeUnschedulable(client, "nonexistent", true)
	if err == nil {
		t.Error("Expected error for nonexistent node")
	}
}
