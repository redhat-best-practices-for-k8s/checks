package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	retry "k8s.io/client-go/util/retry"
)

// Configurable timeouts for pod recreation checks. Tests can override these.
var (
	podRecreationBaseTimeout = 7 * time.Minute
	podRecreationPerPodExtra = time.Minute
	podDeletionGracePeriod   = int64(30)
)

// CheckPodRecreation verifies that pods managed by Deployments and StatefulSets
// are recreated after their node is cordoned and the pods are deleted.
// Nodes hosting the scanner or probe pods are skipped to avoid self-eviction.
func CheckPodRecreation(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	k8sClient, err := getK8sClient(resources)
	if err != nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = err.Error()
		return result
	}

	// Find nodes that host Deployment/StatefulSet pods
	targetNodes := getTargetNodes(resources.Pods)
	if len(targetNodes) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No Deployment or StatefulSet pods found"
		result.Details = append(result.Details, checks.ResourceDetail{
			Kind:      "Node",
			Compliant: true,
			Message:   "No Deployment or StatefulSet pods found to test pod recreation",
		})
		return result
	}

	// Build set of unsafe nodes (scanner + probe pods)
	unsafeNodes := getUnsafeNodes(resources)

	// Filter to safe nodes only
	var safeNodes []string
	for _, node := range targetNodes {
		if !unsafeNodes[node] {
			safeNodes = append(safeNodes, node)
		}
	}

	if len(safeNodes) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "All target nodes host scanner or probe pods; cannot safely cordon"
		result.Details = append(result.Details, checks.ResourceDetail{
			Kind:      "Node",
			Compliant: true,
			Message:   "All target nodes host scanner or probe pods; cannot safely cordon",
		})
		return result
	}

	var failures int
	for _, nodeName := range safeNodes {
		nodeResult := testNodePodRecreation(k8sClient, resources.Pods, nodeName)
		result.Details = append(result.Details, nodeResult.details...)
		if !nodeResult.passed {
			failures++
		}
	}

	if failures > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d node(s) failed pod recreation test", failures)
	}

	return result
}

type nodeTestResult struct {
	passed  bool
	details []checks.ResourceDetail
}

func testNodePodRecreation(client kubernetes.Interface, pods []corev1.Pod, nodeName string) nodeTestResult {
	result := nodeTestResult{passed: true}

	// Cordon the node
	if err := setNodeUnschedulable(client, nodeName, true); err != nil {
		result.passed = false
		result.details = append(result.details, checks.ResourceDetail{
			Kind:      "Node",
			Name:      nodeName,
			Compliant: false,
			Message:   fmt.Sprintf("Failed to cordon node: %v", err),
		})
		return result
	}

	// Always uncordon on exit
	defer func() {
		_ = setNodeUnschedulable(client, nodeName, false)
	}()

	// Find and delete managed pods on this node (skip DaemonSet pods)
	podsOnNode := getManagedPodsOnNode(pods, nodeName)
	if len(podsOnNode) == 0 {
		result.details = append(result.details, checks.ResourceDetail{
			Kind:      "Node",
			Name:      nodeName,
			Compliant: true,
			Message:   "No managed pods on node to test",
		})
		return result
	}

	// Delete each pod
	for i := range podsOnNode {
		pod := &podsOnNode[i]
		gracePeriod := podDeletionGracePeriod
		err := client.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{
			GracePeriodSeconds: &gracePeriod,
		})
		if err != nil {
			result.passed = false
			result.details = append(result.details, checks.ResourceDetail{
				Kind:      "Pod",
				Name:      fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
				Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Failed to delete pod: %v", err),
			})
		}
	}

	// Uncordon before waiting for recreation so pods can be rescheduled
	if err := setNodeUnschedulable(client, nodeName, false); err != nil {
		result.passed = false
		result.details = append(result.details, checks.ResourceDetail{
			Kind:      "Node",
			Name:      nodeName,
			Compliant: false,
			Message:   fmt.Sprintf("Failed to uncordon node: %v", err),
		})
		return result
	}

	// Wait for owning Deployments/StatefulSets to become ready
	timeout := podRecreationBaseTimeout + (podRecreationPerPodExtra * time.Duration(len(podsOnNode)))
	ownerSets := getOwnerSets(podsOnNode)

	allReady := true
	for _, owner := range ownerSets {
		var err error
		switch owner.kind {
		case "Deployment":
			err = waitForDeploymentReady(client, owner.namespace, owner.name, timeout)
		case "StatefulSet":
			err = waitForStatefulSetReady(client, owner.namespace, owner.name, timeout)
		}

		resourceName := fmt.Sprintf("%s/%s", owner.namespace, owner.name)
		if err != nil {
			allReady = false
			result.details = append(result.details, checks.ResourceDetail{
				Kind:      owner.kind,
				Name:      resourceName,
				Namespace: owner.namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Pods not recreated after drain: %v", err),
			})
		} else {
			result.details = append(result.details, checks.ResourceDetail{
				Kind:      owner.kind,
				Name:      resourceName,
				Namespace: owner.namespace,
				Compliant: true,
				Message:   "Pods recreated successfully after drain",
			})
		}
	}

	if !allReady {
		result.passed = false
	}

	return result
}

// getUnsafeNodes returns a set of node names that should not be cordoned.
func getUnsafeNodes(resources *checks.DiscoveredResources) map[string]bool {
	unsafe := make(map[string]bool)

	// Scanner pod node
	if resources.ScannerPodNodeName != "" {
		unsafe[resources.ScannerPodNodeName] = true
	}

	// Probe pod nodes
	for nodeName := range resources.ProbePods {
		unsafe[nodeName] = true
	}

	return unsafe
}

// getTargetNodes returns the unique node names hosting Deployment or StatefulSet pods.
func getTargetNodes(pods []corev1.Pod) []string {
	nodeSet := make(map[string]bool)
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == "" {
			continue
		}
		for _, ref := range pod.OwnerReferences {
			if ref.Kind == "ReplicaSet" || ref.Kind == "StatefulSet" {
				nodeSet[pod.Spec.NodeName] = true
				break
			}
		}
	}

	nodes := make([]string, 0, len(nodeSet))
	for node := range nodeSet {
		nodes = append(nodes, node)
	}
	return nodes
}

// getManagedPodsOnNode returns pods on the given node that are owned by
// ReplicaSets (Deployments) or StatefulSets, excluding DaemonSet pods.
func getManagedPodsOnNode(pods []corev1.Pod, nodeName string) []corev1.Pod {
	var managed []corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName != nodeName {
			continue
		}
		if isDaemonSetPod(pod) {
			continue
		}
		for _, ref := range pod.OwnerReferences {
			if ref.Kind == "ReplicaSet" || ref.Kind == "StatefulSet" {
				managed = append(managed, *pod)
				break
			}
		}
	}
	return managed
}

func isDaemonSetPod(pod *corev1.Pod) bool {
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "DaemonSet" {
			return true
		}
	}
	return false
}

type ownerRef struct {
	kind      string
	name      string
	namespace string
}

// getOwnerSets returns the unique Deployment/StatefulSet owners of the given pods.
// For ReplicaSet-owned pods, we derive the Deployment name by looking at the
// ReplicaSet's OwnerReferences. Since we don't have that info here, we use the
// pod-template-hash label convention: Deployment name = ReplicaSet name minus the hash suffix.
func getOwnerSets(pods []corev1.Pod) []ownerRef {
	seen := make(map[string]bool)
	var owners []ownerRef

	for i := range pods {
		pod := &pods[i]
		for _, ref := range pod.OwnerReferences {
			var owner ownerRef
			switch ref.Kind {
			case "ReplicaSet":
				// Derive deployment name from ReplicaSet name
				// ReplicaSet name format: <deployment-name>-<pod-template-hash>
				deployName := deploymentNameFromReplicaSet(ref.Name, pod)
				owner = ownerRef{kind: "Deployment", name: deployName, namespace: pod.Namespace}
			case "StatefulSet":
				owner = ownerRef{kind: "StatefulSet", name: ref.Name, namespace: pod.Namespace}
			default:
				continue
			}

			key := fmt.Sprintf("%s/%s/%s", owner.kind, owner.namespace, owner.name)
			if !seen[key] {
				seen[key] = true
				owners = append(owners, owner)
			}
			break
		}
	}
	return owners
}

// deploymentNameFromReplicaSet derives the Deployment name from a ReplicaSet name.
// Convention: ReplicaSet name is "<deployment>-<pod-template-hash>".
func deploymentNameFromReplicaSet(rsName string, pod *corev1.Pod) string {
	hash, ok := pod.Labels["pod-template-hash"]
	if ok && len(hash) > 0 {
		suffix := "-" + hash
		if len(rsName) > len(suffix) && rsName[len(rsName)-len(suffix):] == suffix {
			return rsName[:len(rsName)-len(suffix)]
		}
	}
	// Fallback: return the ReplicaSet name as-is
	return rsName
}

func setNodeUnschedulable(client kubernetes.Interface, nodeName string, unschedulable bool) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := client.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		node.Spec.Unschedulable = unschedulable
		_, err = client.CoreV1().Nodes().Update(context.TODO(), node, metav1.UpdateOptions{})
		return err
	})
}
