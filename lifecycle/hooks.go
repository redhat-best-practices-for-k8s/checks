package lifecycle

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// lifecycleHookCheckFunc is a function that checks if a container has a specific lifecycle hook.
type lifecycleHookCheckFunc func(container *corev1.Container) bool

// checkLifecycleHook verifies containers have a specific lifecycle hook.
func checkLifecycleHook(resources *checks.DiscoveredResources, checkFunc lifecycleHookCheckFunc, hookName string) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Pods) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No pods found"
		return result
	}

	var count int
	checks.ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
		if !checkFunc(container) {
			count++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Container %q does not have a %s lifecycle hook", container.Name, hookName),
			})
		}
	})
	if count > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d container(s) missing %s hook", count, hookName)
	}
	return result
}

// CheckPreStop verifies containers have a preStop lifecycle hook.
func CheckPreStop(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkLifecycleHook(resources, func(container *corev1.Container) bool {
		return container.Lifecycle != nil && container.Lifecycle.PreStop != nil
	}, "preStop")
}

// CheckPostStart verifies containers have a postStart lifecycle hook.
func CheckPostStart(resources *checks.DiscoveredResources) checks.CheckResult {
	return checkLifecycleHook(resources, func(container *corev1.Container) bool {
		return container.Lifecycle != nil && container.Lifecycle.PostStart != nil
	}, "postStart")
}
