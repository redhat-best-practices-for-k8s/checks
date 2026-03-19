package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	retry "k8s.io/client-go/util/retry"
)

// Configurable timeouts for scaling checks. Tests can override these.
var (
	scalingTimeout     = 5 * time.Minute
	readinessPollDelay = time.Second
)

// CheckDeploymentScaling verifies that Deployments can scale up and down.
func CheckDeploymentScaling(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	k8sClient, err := getK8sClient(resources)
	if err != nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = err.Error()
		return result
	}

	if len(resources.Deployments) == 0 {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "No Deployments found"
		return result
	}

	var failures int
	for i := range resources.Deployments {
		deploy := &resources.Deployments[i]
		name := fmt.Sprintf("%s/%s", deploy.Namespace, deploy.Name)

		if err := scaleDeployment(k8sClient, deploy); err != nil {
			failures++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Deployment",
				Name:      name,
				Namespace: deploy.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Failed to scale: %v", err),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "Deployment",
				Name:      name,
				Namespace: deploy.Namespace,
				Compliant: true,
				Message:   "Scaled up and down successfully",
			})
		}
	}

	if failures > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d Deployment(s) failed to scale", failures)
	}

	return result
}

// CheckStatefulSetScaling verifies that StatefulSets can scale up and down.
func CheckStatefulSetScaling(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	k8sClient, err := getK8sClient(resources)
	if err != nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = err.Error()
		return result
	}

	if len(resources.StatefulSets) == 0 {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "No StatefulSets found"
		return result
	}

	var failures int
	for i := range resources.StatefulSets {
		sts := &resources.StatefulSets[i]
		name := fmt.Sprintf("%s/%s", sts.Namespace, sts.Name)

		if err := scaleStatefulSet(k8sClient, sts); err != nil {
			failures++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "StatefulSet",
				Name:      name,
				Namespace: sts.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Failed to scale: %v", err),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "StatefulSet",
				Name:      name,
				Namespace: sts.Namespace,
				Compliant: true,
				Message:   "Scaled up and down successfully",
			})
		}
	}

	if failures > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d StatefulSet(s) failed to scale", failures)
	}

	return result
}

func getK8sClient(resources *checks.DiscoveredResources) (kubernetes.Interface, error) {
	if resources.K8sClientset == nil {
		return nil, fmt.Errorf("K8sClientset not available")
	}
	k8sClient, ok := resources.K8sClientset.(kubernetes.Interface)
	if !ok {
		return nil, fmt.Errorf("K8sClientset is not a valid kubernetes.Interface")
	}
	return k8sClient, nil
}

func scaleDeployment(client kubernetes.Interface, deploy *appsv1.Deployment) error {
	var originalReplicas int32 = 1
	if deploy.Spec.Replicas != nil {
		originalReplicas = *deploy.Spec.Replicas
	}

	// Scale in one direction, then restore
	if originalReplicas <= 1 {
		// Scale up then back down
		if err := setDeploymentReplicas(client, deploy.Namespace, deploy.Name, originalReplicas+1); err != nil {
			return fmt.Errorf("scale up: %w", err)
		}
		if err := waitForDeploymentReady(client, deploy.Namespace, deploy.Name, scalingTimeout); err != nil {
			// Try to restore before returning error
			_ = setDeploymentReplicas(client, deploy.Namespace, deploy.Name, originalReplicas)
			return fmt.Errorf("not ready after scale up: %w", err)
		}
		if err := setDeploymentReplicas(client, deploy.Namespace, deploy.Name, originalReplicas); err != nil {
			return fmt.Errorf("scale down: %w", err)
		}
	} else {
		// Scale down then back up
		if err := setDeploymentReplicas(client, deploy.Namespace, deploy.Name, originalReplicas-1); err != nil {
			return fmt.Errorf("scale down: %w", err)
		}
		if err := waitForDeploymentReady(client, deploy.Namespace, deploy.Name, scalingTimeout); err != nil {
			_ = setDeploymentReplicas(client, deploy.Namespace, deploy.Name, originalReplicas)
			return fmt.Errorf("not ready after scale down: %w", err)
		}
		if err := setDeploymentReplicas(client, deploy.Namespace, deploy.Name, originalReplicas); err != nil {
			return fmt.Errorf("scale up: %w", err)
		}
	}

	return waitForDeploymentReady(client, deploy.Namespace, deploy.Name, scalingTimeout)
}

func setDeploymentReplicas(client kubernetes.Interface, namespace, name string, replicas int32) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dp, err := client.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		dp.Spec.Replicas = &replicas
		_, err = client.AppsV1().Deployments(namespace).Update(context.TODO(), dp, metav1.UpdateOptions{})
		return err
	})
}

func waitForDeploymentReady(client kubernetes.Interface, namespace, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		dp, err := client.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		desired := int32(1)
		if dp.Spec.Replicas != nil {
			desired = *dp.Spec.Replicas
		}

		if dp.Status.ReadyReplicas == desired &&
			dp.Status.UpdatedReplicas == desired &&
			dp.Status.AvailableReplicas == desired {
			return nil
		}

		time.Sleep(readinessPollDelay)
	}
	return fmt.Errorf("timed out waiting for Deployment %s/%s to be ready", namespace, name)
}

func scaleStatefulSet(client kubernetes.Interface, sts *appsv1.StatefulSet) error {
	var originalReplicas int32 = 1
	if sts.Spec.Replicas != nil {
		originalReplicas = *sts.Spec.Replicas
	}

	if originalReplicas <= 1 {
		if err := setStatefulSetReplicas(client, sts.Namespace, sts.Name, originalReplicas+1); err != nil {
			return fmt.Errorf("scale up: %w", err)
		}
		if err := waitForStatefulSetReady(client, sts.Namespace, sts.Name, scalingTimeout); err != nil {
			_ = setStatefulSetReplicas(client, sts.Namespace, sts.Name, originalReplicas)
			return fmt.Errorf("not ready after scale up: %w", err)
		}
		if err := setStatefulSetReplicas(client, sts.Namespace, sts.Name, originalReplicas); err != nil {
			return fmt.Errorf("scale down: %w", err)
		}
	} else {
		if err := setStatefulSetReplicas(client, sts.Namespace, sts.Name, originalReplicas-1); err != nil {
			return fmt.Errorf("scale down: %w", err)
		}
		if err := waitForStatefulSetReady(client, sts.Namespace, sts.Name, scalingTimeout); err != nil {
			_ = setStatefulSetReplicas(client, sts.Namespace, sts.Name, originalReplicas)
			return fmt.Errorf("not ready after scale down: %w", err)
		}
		if err := setStatefulSetReplicas(client, sts.Namespace, sts.Name, originalReplicas); err != nil {
			return fmt.Errorf("scale up: %w", err)
		}
	}

	return waitForStatefulSetReady(client, sts.Namespace, sts.Name, scalingTimeout)
}

func setStatefulSetReplicas(client kubernetes.Interface, namespace, name string, replicas int32) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ss, err := client.AppsV1().StatefulSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		ss.Spec.Replicas = &replicas
		_, err = client.AppsV1().StatefulSets(namespace).Update(context.TODO(), ss, metav1.UpdateOptions{})
		return err
	})
}

func waitForStatefulSetReady(client kubernetes.Interface, namespace, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ss, err := client.AppsV1().StatefulSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		desired := int32(1)
		if ss.Spec.Replicas != nil {
			desired = *ss.Spec.Replicas
		}

		if ss.Status.ReadyReplicas == desired {
			return nil
		}

		time.Sleep(readinessPollDelay)
	}
	return fmt.Errorf("timed out waiting for StatefulSet %s/%s to be ready", namespace, name)
}
