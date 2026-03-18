// Package checks provides shared best-practice check implementations
// for Kubernetes workloads. It is designed to be consumed by both the
// certsuite CLI and the bps-operator.
package checks

import (
	"context"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	olmv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	olmpackagev1 "github.com/operator-framework/operator-lifecycle-manager/pkg/package-server/apis/operators/v1"
	apiserverv1 "github.com/openshift/api/apiserver/v1"
	configv1 "github.com/openshift/api/config/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// DiscoveredResources holds all resources discovered in the target namespace.
type DiscoveredResources struct {
	Pods                 []corev1.Pod
	Services             []corev1.Service
	ServiceAccounts      []corev1.ServiceAccount
	Roles                []rbacv1.Role
	RoleBindings         []rbacv1.RoleBinding
	ClusterRoleBindings  []rbacv1.ClusterRoleBinding
	CRDs                 []apiextv1.CustomResourceDefinition
	Namespaces           []string
	ProbePods            map[string]*corev1.Pod // node name -> probe pod
	Deployments          []appsv1.Deployment
	StatefulSets         []appsv1.StatefulSet
	DaemonSets           []appsv1.DaemonSet
	NetworkPolicies      []networkingv1.NetworkPolicy
	ResourceQuotas       []corev1.ResourceQuota
	Nodes                []corev1.Node
	PersistentVolumes    []corev1.PersistentVolume
	StorageClasses       []storagev1.StorageClass
	PodDisruptionBudgets []policyv1.PodDisruptionBudget
	CSVs                 []olmv1alpha1.ClusterServiceVersion

	// OpenShift-specific resources
	ClusterVersion   *configv1.ClusterVersion
	ClusterOperators []configv1.ClusterOperator

	// OLM resources
	CatalogSources   []olmv1alpha1.CatalogSource
	PackageManifests []olmpackagev1.PackageManifest
	Subscriptions    []olmv1alpha1.Subscription

	// API monitoring
	APIRequestCounts []apiserverv1.APIRequestCount

	// Networking
	NetworkAttachmentDefinitions []netattdefv1.NetworkAttachmentDefinition
	SriovNetworks                []unstructured.Unstructured
	SriovNetworkNodePolicies     []unstructured.Unstructured

	// Cluster metadata
	K8sVersion       string
	OpenshiftVersion string
	OCPStatus        string // Lifecycle status: "GA", "MS", "EOL", "PreGA"

	// Execution helpers (injected by certsuite adapter)
	ProbeExecutor ProbeExecutor
	K8sClientset  interface{} // kubernetes.Interface - avoid import

	// ScannerPodNodeName is the node where the scanner pod runs.
	// Mutation checks (cordon/drain) will skip this node to avoid self-eviction.
	// Empty when the scanner runs outside the cluster.
	ScannerPodNodeName string
}

// ProbeExecutor allows checks to exec commands in containers.
type ProbeExecutor interface {
	ExecCommand(ctx context.Context, pod *corev1.Pod, command string) (stdout, stderr string, err error)
}

// CheckFunc is the signature for a best practice check function.
type CheckFunc func(resources *DiscoveredResources) CheckResult

// CheckResult holds the outcome of a single check.
type CheckResult struct {
	ComplianceStatus string
	Reason           string
	Details          []ResourceDetail
}

// ResourceDetail describes a specific resource's compliance status.
type ResourceDetail struct {
	Kind      string
	Name      string
	Namespace string
	Compliant bool
	Message   string
}

// CheckInfo describes a registered check.
type CheckInfo struct {
	Name        string
	Category    string
	Description string
	Remediation string
	CatalogID   string // Anchor in certsuite CATALOG.md
	Fn          CheckFunc
}
