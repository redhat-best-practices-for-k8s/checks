package certification

import (
	"context"
	"fmt"

	"github.com/redhat-best-practices-for-k8s/checks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckHelmVersion verifies that Helm v3 is in use by checking for Tiller pods.
// Tiller was the server-side component of Helm v2 and has known security risks.
func CheckHelmVersion(resources *checks.DiscoveredResources) checks.CheckResult {
	if len(resources.HelmChartReleases) == 0 {
		return checks.CheckResult{
			ComplianceStatus: checks.StatusSkipped,
			Reason:           "No Helm chart releases to check",
		}
	}

	clientset, ok := resources.K8sClientset.(kubernetes.Interface)
	if !ok || clientset == nil {
		return checks.CheckResult{
			ComplianceStatus: checks.StatusSkipped,
			Reason:           "K8s clientset not available",
		}
	}

	podList, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		LabelSelector: "app=helm,name=tiller",
	})
	if err != nil {
		return checks.CheckResult{
			ComplianceStatus: checks.StatusNonCompliant,
			Reason:           fmt.Sprintf("Could not list Tiller pods: %v", err),
		}
	}

	if len(podList.Items) == 0 {
		details := make([]checks.ResourceDetail, 0, len(resources.HelmChartReleases))
		for _, helm := range resources.HelmChartReleases {
			details = append(details, checks.ResourceDetail{
				Kind:      "HelmRelease",
				Name:      helm.Name,
				Namespace: helm.Namespace,
				Compliant: true,
				Message:   "Helm chart was installed with Helm v3",
			})
		}
		return checks.CheckResult{
			ComplianceStatus: checks.StatusCompliant,
			Reason:           "No Tiller pods found; Helm version is v3",
			Details:          details,
		}
	}

	details := tillerPodDetails(podList.Items)
	return checks.CheckResult{
		ComplianceStatus: checks.StatusNonCompliant,
		Reason:           "Tiller pod found; Helm version is v2 but v3 is required",
		Details:          details,
	}
}

func tillerPodDetails(pods []corev1.Pod) []checks.ResourceDetail {
	details := make([]checks.ResourceDetail, 0, len(pods))
	for i := range pods {
		details = append(details, checks.ResourceDetail{
			Kind:      "Pod",
			Name:      pods[i].Name,
			Namespace: pods[i].Namespace,
			Compliant: false,
			Message:   "Tiller pod detected; Helm v2 poses security risks, upgrade to Helm v3",
		})
	}
	return details
}
