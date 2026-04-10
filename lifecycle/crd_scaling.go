package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/redhat-best-practices-for-k8s/checks"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/scale"
	retry "k8s.io/client-go/util/retry"
)

// CheckCRDScaling verifies that custom resources with the scale subresource
// can scale up and down.
func CheckCRDScaling(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	scaleClient, err := getScaleClient(resources)
	if err != nil {
		result.ComplianceStatus = checks.StatusError
		result.Reason = err.Error()
		return result
	}

	if len(resources.ScalableResources) == 0 {
		result.ComplianceStatus = checks.StatusCompliant
		result.Reason = "No scalable custom resources found"
		result.Details = append(result.Details, checks.ResourceDetail{
			Kind:      "CustomResource",
			Compliant: true,
			Message:   "No scalable custom resources found",
		})
		return result
	}

	var failures int
	for i := range resources.ScalableResources {
		cr := &resources.ScalableResources[i]
		name := fmt.Sprintf("%s/%s", cr.Namespace, cr.Name)

		if err := scaleCRD(scaleClient, cr); err != nil {
			failures++
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "CustomResource",
				Name:      name,
				Namespace: cr.Namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Failed to scale: %v", err),
			})
		} else {
			result.Details = append(result.Details, checks.ResourceDetail{
				Kind:      "CustomResource",
				Name:      name,
				Namespace: cr.Namespace,
				Compliant: true,
				Message:   "Scaled up and down successfully",
			})
		}
	}

	if failures > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d custom resource(s) failed to scale", failures)
	}

	return result
}

func getScaleClient(resources *checks.DiscoveredResources) (scale.ScalesGetter, error) {
	if resources.ScaleClient == nil {
		return nil, fmt.Errorf("ScaleClient not available")
	}
	sc, ok := resources.ScaleClient.(scale.ScalesGetter)
	if !ok {
		return nil, fmt.Errorf("ScaleClient is not a valid scale.ScalesGetter")
	}
	return sc, nil
}

func scaleCRD(scaleClient scale.ScalesGetter, cr *checks.ScalableResource) error {
	originalReplicas := cr.Replicas

	if originalReplicas <= 1 {
		// Scale up then back down
		if err := setCRDReplicas(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas+1); err != nil {
			return fmt.Errorf("scale up: %w", err)
		}
		if err := waitForCRDScaleReady(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas+1, scalingTimeout); err != nil {
			_ = setCRDReplicas(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas)
			return fmt.Errorf("not ready after scale up: %w", err)
		}
		if err := setCRDReplicas(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas); err != nil {
			return fmt.Errorf("scale down: %w", err)
		}
	} else {
		// Scale down then back up
		if err := setCRDReplicas(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas-1); err != nil {
			return fmt.Errorf("scale down: %w", err)
		}
		if err := waitForCRDScaleReady(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas-1, scalingTimeout); err != nil {
			_ = setCRDReplicas(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas)
			return fmt.Errorf("not ready after scale down: %w", err)
		}
		if err := setCRDReplicas(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas); err != nil {
			return fmt.Errorf("scale up: %w", err)
		}
	}

	return waitForCRDScaleReady(scaleClient, cr.Namespace, cr.Name, cr.GroupResource, originalReplicas, scalingTimeout)
}

func setCRDReplicas(scaleClient scale.ScalesGetter, namespace, name string, gr schema.GroupResource, replicas int32) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		scaleObj, err := scaleClient.Scales(namespace).Get(context.TODO(), gr, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		scaleObj.Spec.Replicas = replicas
		_, err = scaleClient.Scales(namespace).Update(context.TODO(), gr, scaleObj, metav1.UpdateOptions{})
		return err
	})
}

func waitForCRDScaleReady(scaleClient scale.ScalesGetter, namespace, name string, gr schema.GroupResource, desired int32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		scaleObj, err := scaleClient.Scales(namespace).Get(context.TODO(), gr, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if scaleObj.Status.Replicas == desired {
			return nil
		}

		time.Sleep(readinessPollDelay)
	}
	return fmt.Errorf("timed out waiting for CR %s/%s to reach %d replicas", namespace, name, desired)
}
