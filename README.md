# checks

Shared best-practice check library for Kubernetes workloads. This Go module provides reusable compliance checks consumed by both the [certsuite](https://github.com/redhat-best-practices-for-k8s/certsuite) CLI and the [bps-operator](https://github.com/sebrandon1/bps-operator).

## Architecture

Each check is a pure function with the signature:

```go
type CheckFunc func(resources *DiscoveredResources) CheckResult
```

Checks receive a `DiscoveredResources` struct containing Kubernetes objects (Pods, Services, Deployments, Nodes, CSVs, etc.) and return a `CheckResult` with a compliance status (`Compliant`, `NonCompliant`, or `Skipped`), a reason string, and optional per-resource details.

Checks self-register via `init()` functions in each category package. Consumers import the desired category packages as blank imports to populate the global registry:

```go
import (
    _ "github.com/redhat-best-practices-for-k8s/checks/accesscontrol"
    _ "github.com/redhat-best-practices-for-k8s/checks/lifecycle"
    _ "github.com/redhat-best-practices-for-k8s/checks/networking"
    // ...
)
```

Then query the registry:

```go
// All registered checks
all := checks.All()

// Filter by name
selected := checks.Filtered([]string{"access-control-pod-host-network", "lifecycle-liveness-probe"})

// Filter by category
acChecks := checks.ByCategory("access-control")
```

## Check Categories

| Category | Checks | Description |
|---|---|---|
| `accesscontrol` | 28 | Security context, capabilities, RBAC, host access, namespaces |
| `lifecycle` | 15 | Probes, scheduling, HA, storage, image pull policy |
| `networking` | 5 | Dual-stack, network policies, reserved ports, SR-IOV |
| `observability` | 3 | CRD status, termination policy, pod disruption budgets |
| `performance` | 6 | CPU pinning, exec probes, memory limits, exclusive CPU pools |
| `platform` | 9 | Boot params, hugepages, sysctl, SELinux, node count |
| `operator` | 10 | OLM install status, versioning, CRD ownership, skip range |
| `manageability` | 2 | Port naming, image tags |
| **Total** | **78** | |

## Checks Reference

Check names link to their corresponding test documentation in the [certsuite CATALOG.md](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md).

### access-control

| Check Name | Description |
|---|---|
| [`access-control-sys-admin-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-sys-admin-capability-check) | Containers do not have SYS_ADMIN capability |
| [`access-control-net-admin-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-net-admin-capability-check) | Containers do not have NET_ADMIN capability |
| [`access-control-net-raw-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-net-raw-capability-check) | Containers do not have NET_RAW capability |
| [`access-control-ipc-lock-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-ipc-lock-capability-check) | Containers do not have IPC_LOCK capability |
| [`access-control-bpf-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-bpf-capability-check) | Containers do not have BPF capability |
| [`access-control-pod-host-network`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-host-network) | Pods do not use HostNetwork |
| [`access-control-pod-host-path`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-host-path) | Pods do not use HostPath volumes |
| [`access-control-pod-host-ipc`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-host-ipc) | Pods do not use HostIPC |
| [`access-control-pod-host-pid`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-host-pid) | Pods do not use HostPID |
| [`access-control-container-host-port`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-container-host-port) | Containers do not use HostPort |
| [`access-control-security-context-non-root-user-id-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-security-context-non-root-user-id-check) | Containers set runAsNonRoot |
| [`access-control-security-context-privilege-escalation`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-security-context-privilege-escalation) | Containers disallow privilege escalation |
| [`access-control-security-context-read-only-file-system`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-security-context-read-only-file-system) | Containers use read-only root filesystem |
| [`access-control-no-1337-uid`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-no-1337-uid) | Containers do not run as UID 1337 (Istio reserved) |
| [`access-control-security-context`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-security-context) | Security context classification (SCC level) |
| [`access-control-pod-service-account`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-service-account) | Pods use dedicated service accounts |
| [`access-control-pod-role-bindings`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-role-bindings) | RoleBindings only reference target namespace SAs |
| [`access-control-cluster-role-bindings`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-cluster-role-bindings) | Pod SAs are not bound to ClusterRoleBindings |
| [`access-control-pod-automount-service-account-token`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-automount-service-account-token) | Pods do not automount SA tokens |
| [`access-control-service-type`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-service-type) | Services do not use NodePort |
| [`access-control-namespace`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-namespace) | Pods run in allowed namespaces |
| [`access-control-namespace-resource-quota`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-namespace-resource-quota) | Namespaces have ResourceQuotas |
| [`access-control-requests`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-requests) | Containers have CPU and memory requests |
| [`access-control-sys-ptrace-capability`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-sys-ptrace-capability) | Shared PID namespace pods have SYS_PTRACE |
| [`access-control-crd-roles`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-crd-roles) | Roles only grant CRD permissions |
| [`access-control-one-process-per-container`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-one-process-per-container) | Each container runs one process |
| [`access-control-ssh-daemons`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-ssh-daemons) | No SSH daemons in containers |
| [`access-control-sys-nice-realtime-capability`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-sys-nice-realtime-capability) | RT kernel pods have SYS_NICE capability |

### lifecycle

| Check Name | Description |
|---|---|
| [`lifecycle-startup-probe`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-startup-probe) | Containers have startupProbe |
| [`lifecycle-readiness-probe`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-readiness-probe) | Containers have readinessProbe |
| [`lifecycle-liveness-probe`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-liveness-probe) | Containers have livenessProbe |
| [`lifecycle-container-prestop`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-container-prestop) | Containers have preStop hook |
| [`lifecycle-container-poststart`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-container-poststart) | Containers have postStart hook |
| [`lifecycle-image-pull-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-image-pull-policy) | imagePullPolicy is Always or uses digest |
| [`lifecycle-pod-owner-type`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-owner-type) | Pods owned by ReplicaSet/StatefulSet/DaemonSet |
| [`lifecycle-pod-scheduling`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-scheduling) | Pods have scheduling directives |
| [`lifecycle-pod-high-availability`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-high-availability) | Deployments have replicas > 1 |
| [`lifecycle-cpu-isolation`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-cpu-isolation) | CPU requests equal CPU limits |
| [`lifecycle-affinity-required-pods`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-affinity-required-pods) | Pods have anti-affinity rules |
| [`lifecycle-pod-toleration-bypass`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-toleration-bypass) | No unnecessary master taint tolerations |
| [`lifecycle-persistent-volume-reclaim-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-persistent-volume-reclaim-policy) | PV reclaimPolicy is not Delete |
| [`lifecycle-storage-provisioner`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-storage-provisioner) | StorageClass has valid provisioner |
| [`lifecycle-topology-spread-constraint`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-topology-spread-constraint) | TopologySpreadConstraints cover hostname and zone |

### networking

| Check Name | Description |
|---|---|
| [`networking-dual-stack-service`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-dual-stack-service) | Services support dual-stack |
| [`networking-network-policy-deny-all`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-network-policy-deny-all) | Default-deny NetworkPolicy exists |
| [`networking-reserved-partner-ports`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-reserved-partner-ports) | No use of reserved partner ports |
| [`networking-ocp-reserved-ports-usage`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-ocp-reserved-ports-usage) | No use of OCP reserved ports |
| [`networking-restart-on-reboot-sriov-pod`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-restart-on-reboot-sriov-pod) | SR-IOV pods have restart label |

### observability

| Check Name | Description |
|---|---|
| [`observability-crd-status`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#observability-crd-status) | CRDs define status subresource |
| [`observability-termination-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#observability-termination-policy) | terminationMessagePolicy is FallbackToLogsOnError |
| [`observability-pod-disruption-budget`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#observability-pod-disruption-budget) | PDBs exist for HA workloads |

### performance

| Check Name | Description |
|---|---|
| [`performance-exclusive-cpu-pool`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-exclusive-cpu-pool) | Whole-CPU containers use Guaranteed QoS |
| [`performance-rt-apps-no-exec-probes`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-rt-apps-no-exec-probes) | RT containers avoid exec probes |
| `performance-limit-memory-allocation` | Containers have memory limits |
| `performance-limited-use-of-exec-probes` | Cluster-wide exec probe count below threshold |
| [`performance-cpu-pinning-no-exec-probes`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-cpu-pinning-no-exec-probes) | CPU-pinned pods avoid exec probes |
| [`performance-max-resources-exec-probes`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-max-resources-exec-probes) | Exec probes have periodSeconds >= 10 |

### platform

| Check Name | Description |
|---|---|
| [`platform-alteration-boot-params`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-boot-params) | No non-standard kernel boot parameters |
| [`platform-alteration-hugepages-config`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-hugepages-config) | Hugepage configuration is consistent |
| [`platform-alteration-sysctl-config`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-sysctl-config) | Sysctl settings managed via MachineConfig |
| [`platform-alteration-tainted-node-kernel`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-tainted-node-kernel) | Kernel is not tainted |
| [`platform-alteration-service-mesh-usage`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-service-mesh-usage) | Pods do not use Istio sidecars |
| [`platform-alteration-hugepages-2m-only`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-hugepages-2m-only) | Only 2Mi hugepages used |
| `platform-alteration-ocp-node-count` | Minimum worker node count met |
| [`platform-alteration-hugepages-1g-only`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-hugepages-1g-only) | Only 1Gi hugepages used |
| [`platform-alteration-is-selinux-enforcing`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-is-selinux-enforcing) | SELinux is in Enforcing mode |

### operator

| Check Name | Description |
|---|---|
| [`operator-install-status-succeeded`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-install-status-succeeded) | CSVs report Succeeded status |
| [`operator-install-status-no-privileges`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-install-status-no-privileges) | CSVs do not grant SCC access |
| [`operator-install-source`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-install-source) | Operators installed via OLM |
| [`operator-semantic-versioning`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-semantic-versioning) | CSVs use semantic versioning |
| [`operator-crd-versioning`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-crd-versioning) | CRD versions follow K8s conventions |
| [`operator-crd-openapi-schema`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-crd-openapi-schema) | CRDs have OpenAPI v3 schema |
| [`operator-single-crd-owner`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-single-crd-owner) | Each CRD owned by one operator |
| [`operator-pods-no-hugepages`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-pods-no-hugepages) | Operator pods do not request hugepages |
| [`operator-olm-skip-range`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-olm-skip-range) | CSVs have olm.skipRange annotation |
| [`operator-multiple-same-operators`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-multiple-same-operators) | No duplicate operator installations |

### manageability

| Check Name | Description |
|---|---|
| [`manageability-container-port-name-format`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#manageability-container-port-name-format) | Port names follow IANA conventions |
| [`manageability-containers-image-tag`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#manageability-containers-image-tag) | Images use specific tag or digest |

## Probe-Based Checks

Some checks in `accesscontrol` and `platform` require runtime inspection via the `ProbeExecutor` interface:

```go
type ProbeExecutor interface {
    ExecCommand(ctx context.Context, pod *corev1.Pod, command string) (stdout, stderr string, err error)
}
```

Set `DiscoveredResources.ProbeExecutor` and `DiscoveredResources.ProbePods` to enable these checks. Without a probe executor, they return `Skipped`.

## Usage

```go
package main

import (
    "fmt"

    "github.com/redhat-best-practices-for-k8s/checks"

    // Register all check categories
    _ "github.com/redhat-best-practices-for-k8s/checks/accesscontrol"
    _ "github.com/redhat-best-practices-for-k8s/checks/lifecycle"
    _ "github.com/redhat-best-practices-for-k8s/checks/manageability"
    _ "github.com/redhat-best-practices-for-k8s/checks/networking"
    _ "github.com/redhat-best-practices-for-k8s/checks/observability"
    _ "github.com/redhat-best-practices-for-k8s/checks/operator"
    _ "github.com/redhat-best-practices-for-k8s/checks/performance"
    _ "github.com/redhat-best-practices-for-k8s/checks/platform"
)

func main() {
    // Build resources from your cluster discovery
    resources := &checks.DiscoveredResources{
        // ... populate with k8s objects
    }

    // Run all checks
    for _, check := range checks.All() {
        result := check.Fn(resources)
        fmt.Printf("%-50s %s\n", check.Name, result.ComplianceStatus)
    }
}
```

## Dependencies

- `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/apiextensions-apiserver` v0.35.1
- `github.com/operator-framework/api` v0.41.0 (for OLM ClusterServiceVersion types)
- Go 1.26.1+

## License

Apache License 2.0
