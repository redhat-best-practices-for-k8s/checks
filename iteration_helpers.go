package checks

import corev1 "k8s.io/api/core/v1"

// ContainerFunc is a callback function that processes a container within a pod.
// It receives the pod and container as parameters to perform validation logic.
type ContainerFunc func(pod *corev1.Pod, container *corev1.Container)

// ForEachPodContainer iterates over all pods and their containers (both init and regular).
// For each container, it calls the provided function with the pod and container.
// This helper eliminates the common boilerplate of:
//
//	for i := range pods {
//	    pod := &pods[i]
//	    allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
//	    for j := range allContainers {
//	        container := &allContainers[j]
//	        // ... validation logic ...
//	    }
//	}
//
// Example usage:
//
//	var count int
//	ForEachPodContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
//	    if container.SecurityContext == nil {
//	        count++
//	        result.Details = append(result.Details, ResourceDetail{
//	            Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace,
//	            Compliant: false,
//	            Message: fmt.Sprintf("Container %q missing securityContext", container.Name),
//	        })
//	    }
//	})
func ForEachPodContainer(pods []corev1.Pod, fn ContainerFunc) {
	for i := range pods {
		pod := &pods[i]
		for j := range pod.Spec.InitContainers {
			fn(pod, &pod.Spec.InitContainers[j])
		}
		for j := range pod.Spec.Containers {
			fn(pod, &pod.Spec.Containers[j])
		}
	}
}

// ForEachContainer iterates over all pods and their regular containers (excluding init containers).
// For each container, it calls the provided function with the pod and container.
// Use this when init containers should be excluded from the check.
//
// Example usage:
//
//	var count int
//	ForEachContainer(resources.Pods, func(pod *corev1.Pod, container *corev1.Container) {
//	    if container.LivenessProbe == nil {
//	        count++
//	    }
//	})
func ForEachContainer(pods []corev1.Pod, fn ContainerFunc) {
	for i := range pods {
		pod := &pods[i]
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			fn(pod, container)
		}
	}
}
