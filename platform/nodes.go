package platform

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckServiceMeshUsage verifies pods are not injected with Istio/service mesh sidecars.
func CheckServiceMeshUsage(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if pod.Annotations["sidecar.istio.io/inject"] == "true" {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod has Istio sidecar injection enabled",
			})
			continue
		}
		for _, c := range pod.Spec.Containers {
			if c.Name == "istio-proxy" || strings.Contains(c.Image, "istio/proxyv2") {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Pod has service mesh sidecar container %q", c.Name),
				})
				break
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) use service mesh sidecars", count)
	}
	return result
}

// CheckHugepages2MiOnly verifies only 2Mi hugepages are used (not 1Gi).
func CheckHugepages2MiOnly(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			for resourceName := range container.Resources.Requests {
				if resourceName == corev1.ResourceName("hugepages-1Gi") {
					count++
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
						Compliant: false,
						Message:   fmt.Sprintf("Container %q requests 1Gi hugepages", container.Name),
					})
				}
			}
			for resourceName := range container.Resources.Limits {
				if resourceName == corev1.ResourceName("hugepages-1Gi") {
					count++
					result.Details = append(result.Details, checks.ResourceDetail{
						Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
						Compliant: false,
						Message:   fmt.Sprintf("Container %q has 1Gi hugepages limit", container.Name),
					})
				}
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) use 1Gi hugepages (only 2Mi allowed)", count)
	}
	return result
}

// CheckNodeCount verifies the cluster has a minimum number of nodes.
func CheckNodeCount(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if len(resources.Nodes) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No nodes found"
		return result
	}

	workerCount := 0
	for i := range resources.Nodes {
		node := &resources.Nodes[i]
		_, isMaster := node.Labels["node-role.kubernetes.io/master"]
		_, isControlPlane := node.Labels["node-role.kubernetes.io/control-plane"]
		if !isMaster && !isControlPlane {
			workerCount++
		}
	}

	if workerCount < 3 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("Cluster has %d worker node(s), minimum 3 recommended", workerCount)
		result.Details = append(result.Details, checks.ResourceDetail{
			Kind: "Cluster", Name: "nodes",
			Compliant: false,
			Message:   fmt.Sprintf("%d total nodes, %d workers", len(resources.Nodes), workerCount),
		})
	}
	return result
}
