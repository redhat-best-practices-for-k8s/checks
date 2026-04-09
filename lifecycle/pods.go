package lifecycle

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

const affinityRequiredLabel = "AffinityRequired"

// CheckImagePullPolicy verifies imagePullPolicy is IfNotPresent.
func CheckImagePullPolicy(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachPodContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if container.ImagePullPolicy != corev1.PullIfNotPresent {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q has imagePullPolicy %q, must be IfNotPresent", container.Name, container.ImagePullPolicy),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) have non-compliant imagePullPolicy", count)
	}
	return result
}

var allowedOwnerKinds = map[string]bool{
	"ReplicaSet":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"Job":         true,
}

// CheckPodOwnerType verifies pods are owned by a workload controller.
func CheckPodOwnerType(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		if !hasAllowedOwner(pod) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod is not owned by ReplicaSet, StatefulSet, DaemonSet, or Job",
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) are not managed by a workload controller", count)
	}
	return result
}

func hasAllowedOwner(pod *corev1.Pod) bool {
	for _, ref := range pod.OwnerReferences {
		if allowedOwnerKinds[ref.Kind] {
			return true
		}
	}
	return false
}

// CheckPodScheduling verifies pods do not use nodeSelector or nodeAffinity.
// Pods should be schedulable on any node; using nodeSelector or nodeAffinity
// restricts scheduling and is non-compliant.
func CheckPodScheduling(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		hasNodeSelector := len(pod.Spec.NodeSelector) > 0
		hasNodeAffinity := pod.Spec.Affinity != nil && pod.Spec.Affinity.NodeAffinity != nil

		if hasNodeSelector || hasNodeAffinity {
			count++
			var reasons []string
			if hasNodeSelector {
				reasons = append(reasons, fmt.Sprintf("nodeSelector: %v", pod.Spec.NodeSelector))
			}
			if hasNodeAffinity {
				reasons = append(reasons, "nodeAffinity set")
			}
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Pod has scheduling constraints: %s", strings.Join(reasons, ", ")),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) have nodeSelector or nodeAffinity scheduling constraints", count)
	}
	return result
}

// CheckHighAvailability verifies Deployments have replicas > 1.
func CheckHighAvailability(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Deployments) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No deployments found"
		return result
	}

	var count int
	for i := range resources.Deployments {
		deploy := &resources.Deployments[i]
		replicas := int32(1)
		if deploy.Spec.Replicas != nil {
			replicas = *deploy.Spec.Replicas
		}
		if replicas < 2 {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Deployment", Name: deploy.Name, Namespace: deploy.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Deployment has %d replica(s), expected at least 2", replicas),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d deployment(s) have fewer than 2 replicas", count)
	}
	return result
}

// CheckCPUIsolation verifies CPU requests equal CPU limits (Guaranteed QoS for CPU).
func CheckCPUIsolation(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		cpuReq := container.Resources.Requests.Cpu()
		cpuLim := container.Resources.Limits.Cpu()
		if cpuReq.IsZero() || cpuLim.IsZero() || !cpuReq.Equal(*cpuLim) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q CPU requests (%s) != limits (%s)", container.Name, cpuReq.String(), cpuLim.String()),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) do not have CPU requests equal to limits", count)
	}
	return result
}

// CheckAffinityRequired verifies pods with the AffinityRequired label have proper affinity rules.
// Only pods with label AffinityRequired="true" (case-insensitive) are checked.
// Compliant pods must have Affinity set, must NOT have PodAntiAffinity, and must have
// either PodAffinity or NodeAffinity configured.
func CheckAffinityRequired(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var checked int
	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]

		val, ok := pod.Labels[affinityRequiredLabel]
		if !ok || !strings.EqualFold(val, "true") {
			continue
		}
		checked++

		// Affinity must be set
		if pod.Spec.Affinity == nil {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod has AffinityRequired label but no affinity rules configured",
			})
			continue
		}

		// PodAntiAffinity must NOT be set
		if pod.Spec.Affinity.PodAntiAffinity != nil {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod has AffinityRequired label but has anti-affinity rules (not allowed)",
			})
			continue
		}

		// Must have either PodAffinity or NodeAffinity
		if pod.Spec.Affinity.PodAffinity == nil && pod.Spec.Affinity.NodeAffinity == nil {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   "Pod has AffinityRequired label but is missing pod affinity or node affinity rules",
			})
		}
	}

	if checked == 0 {
		result.Reason = "No pods with AffinityRequired label found"
		return result
	}

	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) with AffinityRequired label have non-compliant affinity configuration", count)
	}
	return result
}

const tolerationSecondsDefault = 300

// CheckTolerationBypass verifies pods have not modified default Kubernetes tolerations.
// A toleration is considered modified (non-compliant) if:
//   - Its key does not contain "node.kubernetes.io" (not a default toleration)
//   - It is a node.kubernetes.io/not-ready or node.kubernetes.io/unreachable NoExecute
//     toleration but the operator is not Exists or tolerationSeconds is not 300
//   - It is a node.kubernetes.io/memory-pressure NoSchedule toleration but the operator
//     is not Exists or the pod's QoS class is BestEffort (memory-pressure is only added
//     by default for non-BestEffort pods)
//   - It is any other non-default node.kubernetes.io toleration with a NoExecute,
//     NoSchedule, or PreferNoSchedule effect
func CheckTolerationBypass(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	for i := range resources.Pods {
		pod := &resources.Pods[i]
		for _, tol := range pod.Spec.Tolerations {
			if isTolerationModified(tol, pod.Status.QOSClass) {
				count++
				result.Details = append(result.Details, checks.ResourceDetail{
					Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
					Compliant: false,
					Message:   fmt.Sprintf("Pod has modified toleration: key=%q, effect=%s, operator=%s", tol.Key, tol.Effect, tol.Operator),
				})
				break
			}
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d pod(s) have modified tolerations", count)
	}
	return result
}

// isTolerationModified checks whether a toleration deviates from the default
// tolerations automatically added by Kubernetes. This mirrors the certsuite's
// tolerations.IsTolerationModified logic.
func isTolerationModified(t corev1.Toleration, qosClass corev1.PodQOSClass) bool {
	const (
		notReadyStr       = "node.kubernetes.io/not-ready"
		unreachableStr    = "node.kubernetes.io/unreachable"
		memoryPressureStr = "node.kubernetes.io/memory-pressure"
	)

	// Any toleration key that does not contain "node.kubernetes.io" is considered modified.
	if !strings.Contains(t.Key, "node.kubernetes.io") {
		return true
	}

	switch t.Effect {
	case corev1.TaintEffectNoExecute:
		if t.Key == notReadyStr || t.Key == unreachableStr {
			// Default: operator=Exists, tolerationSeconds=300
			if t.Operator == corev1.TolerationOpExists && t.TolerationSeconds != nil && *t.TolerationSeconds == int64(tolerationSecondsDefault) {
				return false
			}
		}
		return true
	case corev1.TaintEffectNoSchedule:
		// Default memory-pressure toleration: only for non-BestEffort pods
		if t.Key == memoryPressureStr &&
			t.Operator == corev1.TolerationOpExists &&
			qosClass != corev1.PodQOSBestEffort {
			return false
		}
		return true
	case corev1.TaintEffectPreferNoSchedule:
		return true
	}

	return false
}

// CheckPVReclaimPolicy verifies PersistentVolume reclaimPolicy is Delete.
// The Delete reclaim policy is the required/compliant policy, ensuring that
// persistent volumes are cleaned up when no longer needed.
func CheckPVReclaimPolicy(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.PersistentVolumes) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No PersistentVolumes found"
		return result
	}

	var count int
	for i := range resources.PersistentVolumes {
		pv := &resources.PersistentVolumes[i]
		if pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimDelete {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "PersistentVolume", Name: pv.Name,
				Compliant: false,
				Message:   fmt.Sprintf("PersistentVolume reclaimPolicy is %s, must be Delete", pv.Spec.PersistentVolumeReclaimPolicy),
			})
		}
	}
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d PersistentVolume(s) do not have reclaimPolicy Delete", count)
	}
	return result
}

const (
	localStorageProvisioner = "kubernetes.io/no-provisioner"
	lvmProvisioner          = "topolvm.io"
)

// isLocalProvisioner returns true if the provisioner is a local storage provisioner.
func isLocalProvisioner(provisioner string) bool {
	return provisioner == localStorageProvisioner || strings.HasPrefix(provisioner, lvmProvisioner)
}

// CheckStorageProvisioner validates StorageClass provisioners based on cluster topology.
//
// Multi-node clusters: Local storage provisioners (kubernetes.io/no-provisioner and
// topolvm.io) are non-compliant. Non-local storage is compliant.
//
// SNO clusters (single node): Local storage is recommended but only one type is allowed
// (not both no-provisioner AND topolvm). Non-local storage is non-compliant on SNO.
func CheckStorageProvisioner(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.StorageClasses) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No StorageClasses found"
		return result
	}

	isSNO := len(resources.Nodes) == 1

	var nonCompliantCount int
	if isSNO {
		nonCompliantCount = checkStorageProvisionerSNO(resources, &result)
	} else {
		nonCompliantCount = checkStorageProvisionerMultiNode(resources, &result)
	}

	if nonCompliantCount > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d StorageClass(es) have non-compliant provisioner", nonCompliantCount)
	}
	return result
}

// checkStorageProvisionerMultiNode checks storage provisioners for multi-node clusters.
// Local storage is non-compliant; non-local storage is compliant.
func checkStorageProvisionerMultiNode(resources *checks.DiscoveredResources, result *checks.CheckResult) int {
	var count int
	for i := range resources.StorageClasses {
		sc := &resources.StorageClasses[i]
		if isLocalProvisioner(sc.Provisioner) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "StorageClass", Name: sc.Name,
				Compliant: false,
				Message:   fmt.Sprintf("Local storage provisioner %q not recommended in multi-node clusters", sc.Provisioner),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "StorageClass", Name: sc.Name,
				Compliant: true,
				Message:   fmt.Sprintf("Non-local storage provisioner %q recommended in multi-node clusters", sc.Provisioner),
			})
		}
	}
	return count
}

// checkStorageProvisionerSNO checks storage provisioners for single-node (SNO) clusters.
// Local storage is compliant but only one type allowed (not both no-provisioner AND topolvm).
// Non-local storage is non-compliant on SNO.
func checkStorageProvisionerSNO(resources *checks.DiscoveredResources, result *checks.CheckResult) int {
	// Track which local provisioner type was seen first
	snoSingleLocalProvisioner := ""

	var count int
	for i := range resources.StorageClasses {
		sc := &resources.StorageClasses[i]

		if !isLocalProvisioner(sc.Provisioner) {
			// Non-local storage is non-compliant on SNO
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "StorageClass", Name: sc.Name,
				Compliant: false,
				Message:   fmt.Sprintf("Non-local storage provisioner %q not recommended in single-node clusters", sc.Provisioner),
			})
			continue
		}

		// Local provisioner -- determine which type
		provType := sc.Provisioner
		if strings.HasPrefix(provType, lvmProvisioner) {
			provType = lvmProvisioner
		}

		if snoSingleLocalProvisioner == "" {
			// First local provisioner seen -- this is the allowed type
			snoSingleLocalProvisioner = provType
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "StorageClass", Name: sc.Name,
				Compliant: true,
				Message:   fmt.Sprintf("Local storage provisioner %q recommended for SNO clusters", sc.Provisioner),
			})
		} else if provType == snoSingleLocalProvisioner {
			// Same type as the first -- compliant
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "StorageClass", Name: sc.Name,
				Compliant: true,
				Message:   fmt.Sprintf("Local storage provisioner %q recommended for SNO clusters", sc.Provisioner),
			})
		} else {
			// Different local type -- non-compliant (can't use both no-provisioner AND topolvm)
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "StorageClass", Name: sc.Name,
				Compliant: false,
				Message:   "A single type of local storage is recommended for single-node clusters; use either kubernetes.io/no-provisioner or topolvm, but not both",
			})
		}
	}
	return count
}
