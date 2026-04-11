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
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	PersistentVolumes      []corev1.PersistentVolume
	PersistentVolumeClaims []corev1.PersistentVolumeClaim
	StorageClasses         []storagev1.StorageClass
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

	// Helm chart releases discovered in the cluster
	HelmChartReleases []HelmChartRelease

	// Certification validator (backed by oct library)
	CertValidator CertificationValidator

	// Scalable custom resources (CRDs with scale subresource)
	ScalableResources []ScalableResource

	// Scaling configuration (from certsuite config)
	ManagedDeployments      []string           // Names of deployments managed by CRD operators
	ManagedStatefulSets     []string           // Names of statefulsets managed by CRD operators
	SkipScalingDeployments  []SkipScalingEntry // Deployments to skip in scaling tests
	SkipScalingStatefulSets []SkipScalingEntry // StatefulSets to skip in scaling tests
	CRDFilters              []CRDFilter        // CRD filter config for managed workload owner checks

	// CRInstances maps CRD name -> namespace -> []CR name for all custom resource
	// instances discovered in the cluster. Used to validate CRs exist only in
	// configured namespaces.
	CRInstances map[string]map[string][]string

	// PodMultusNetworks maps pod key ("namespace/name") to its Multus network interfaces.
	// Populated by the adapter from the k8s.v1.cni.cncf.io/network-status annotation.
	PodMultusNetworks map[string][]MultusNetwork

	// Execution helpers (injected by certsuite adapter)
	ProbeExecutor ProbeExecutor
	K8sClientset  interface{} // kubernetes.Interface - avoid import
	ScaleClient   interface{} // scale.ScalesGetter - avoid import

	// ScannerPodNodeName is the node where the scanner pod runs.
	// Mutation checks (cordon/drain) will skip this node to avoid self-eviction.
	// Empty when the scanner runs outside the cluster.
	ScannerPodNodeName string
}

// MultusNetwork represents a secondary (non-default) network interface on a pod.
type MultusNetwork struct {
	Name          string   // Network name (e.g., "ns1/my-net-attach")
	InterfaceName string   // Interface name (e.g., "net1")
	IPs           []string // IP addresses on this interface
}

// ScalableResource represents a custom resource that supports the scale subresource.
type ScalableResource struct {
	Name          string
	Namespace     string
	Replicas      int32
	GroupResource schema.GroupResource
}

// CRDInfo holds the name and kind of a CRD, used for owner reference checks
// without requiring the full apiextv1.CustomResourceDefinition type.
type CRDInfo struct {
	Name string // Full CRD name (e.g., "myresources.example.com")
	Kind string // CRD kind (e.g., "MyResource")
}

// SkipScalingEntry identifies a workload to skip in scaling tests by name and namespace.
type SkipScalingEntry struct {
	Name      string
	Namespace string
}

// CRDFilter defines a CRD config filter used to determine if a managed workload's
// owner CRD is scalable.
type CRDFilter struct {
	NameSuffix string
	Scalable   bool
}

// ProbeExecutor allows checks to exec commands in containers.
type ProbeExecutor interface {
	// ExecCommand executes a command in the first container of the given pod.
	ExecCommand(ctx context.Context, pod *corev1.Pod, command string) (stdout, stderr string, err error)
	// ExecCommandInContainer executes a command in a specific container of the given pod.
	ExecCommandInContainer(ctx context.Context, pod *corev1.Pod, containerName, command string) (stdout, stderr string, err error)
}

// HelmChartRelease represents a Helm chart release discovered in the cluster.
type HelmChartRelease struct {
	Name      string
	Namespace string
	Version   string // Chart version (e.g., "1.2.3")
}

// CertificationValidator checks certification status of containers, operators, and Helm charts.
// This is a simplified interface that avoids importing helm.sh/helm/v3 into the checks library.
// The certsuite adapter wraps oct's CertificationStatusValidator to implement this interface.
type CertificationValidator interface {
	IsContainerCertified(registry, repository, tag, digest string) bool
	IsOperatorCertified(csvName, ocpVersion string) bool
	IsHelmChartCertified(chartName, chartVersion, kubeVersion string) bool
}

// Compliance status constants used by all check functions.
const (
	StatusCompliant    = "Compliant"
	StatusNonCompliant = "NonCompliant"
	StatusSkipped      = "Skipped"
	StatusError        = "Error"
)

// IgnoredContainerName is a container name that should be excluded from checks.
// Istio-proxy sidecars are injected by the service mesh and are not part of the workload.
const IgnoredContainerName = "istio-proxy"

// IsIgnoredContainer returns true if the container name should be skipped by checks.
func IsIgnoredContainer(name string) bool {
	return name == IgnoredContainerName
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

	// Metadata fields (migrated from certsuite identifiers)
	Tags                   []string          // e.g. ["common"] or ["telco","faredge"]
	BestPracticeReference  string            // doc link URL
	ExceptionProcess       string            // exception handling procedure
	ImpactStatement        string            // consequences of failing this check
	CategoryClassification map[string]string // FarEdge/Telco/NonTelco/Extended -> Mandatory/Optional
	Qe                     bool              // whether QE automated test exists
}
