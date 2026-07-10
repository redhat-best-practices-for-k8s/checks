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
| `certification` | 4 | Container, operator, and Helm chart Red Hat certification |
| `lifecycle` | 19 | Probes, scheduling, HA, scaling, storage, image pull policy |
| `manageability` | 2 | Port naming, image tags |
| `networking` | 11 | Dual-stack, ICMP connectivity, network policies, reserved ports, SR-IOV |
| `observability` | 5 | CRD status, termination policy, pod disruption budgets, logging, API compat |
| `operator` | 12 | OLM install status, versioning, CRD ownership, skip range, namespacing |
| `performance` | 9 | CPU pinning, exec probes, memory limits, scheduling policies |
| `platform` | 15 | Boot params, hugepages, sysctl, SELinux, base image, OCP lifecycle |
| **Total** | **105** | |

## Checks Reference

Check names link to their corresponding test documentation in the [certsuite CATALOG.md](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md).

### access-control

| Check Name | Description | Covered by UT |
|---|---|---|
| [`access-control-sys-admin-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-sys-admin-capability-check) | Containers do not have SYS_ADMIN capability | Yes |
| [`access-control-net-admin-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-net-admin-capability-check) | Containers do not have NET_ADMIN capability | Yes |
| [`access-control-net-raw-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-net-raw-capability-check) | Containers do not have NET_RAW capability | Yes |
| [`access-control-ipc-lock-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-ipc-lock-capability-check) | Containers do not have IPC_LOCK capability | Yes |
| [`access-control-bpf-capability-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-bpf-capability-check) | Containers do not have BPF capability | Yes |
| [`access-control-pod-host-network`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-host-network) | Pods do not use HostNetwork | Yes |
| [`access-control-pod-host-path`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-host-path) | Pods do not use HostPath volumes | Yes |
| [`access-control-pod-host-ipc`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-host-ipc) | Pods do not use HostIPC | Yes |
| [`access-control-pod-host-pid`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-host-pid) | Pods do not use HostPID | Yes |
| [`access-control-container-host-port`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-container-host-port) | Containers do not use HostPort | Yes |
| [`access-control-security-context-non-root-user-id-check`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-security-context-non-root-user-id-check) | Containers set runAsNonRoot | Yes |
| [`access-control-security-context-privilege-escalation`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-security-context-privilege-escalation) | Containers disallow privilege escalation | Yes |
| [`access-control-security-context-read-only-root-file-system`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-security-context-read-only-root-file-system) | Containers use read-only root filesystem | Yes |
| [`access-control-no-1337-uid`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-no-1337-uid) | Containers do not run as UID 1337 (Istio reserved) | Yes |
| [`access-control-security-context`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-security-context) | Security context classification (SCC level) | Yes |
| [`access-control-pod-service-account`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-service-account) | Pods use dedicated service accounts | Yes |
| [`access-control-pod-role-bindings`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-role-bindings) | RoleBindings only reference target namespace SAs | Yes |
| [`access-control-cluster-role-bindings`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-cluster-role-bindings) | Pod SAs are not bound to ClusterRoleBindings | Yes |
| [`access-control-pod-automount-service-account-token`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-pod-automount-service-account-token) | Pods do not automount SA tokens | Yes |
| [`access-control-service-type`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-service-type) | Services do not use NodePort | Yes |
| [`access-control-namespace`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-namespace) | Pods run in allowed namespaces | Yes |
| [`access-control-namespace-resource-quota`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-namespace-resource-quota) | Namespaces have ResourceQuotas | Yes |
| [`access-control-requests`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-requests) | Containers have CPU and memory requests | Yes |
| [`access-control-sys-ptrace-capability`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-sys-ptrace-capability) | Shared PID namespace pods have SYS_PTRACE | Yes |
| [`access-control-crd-roles`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-crd-roles) | Roles only grant CRD permissions | Yes |
| [`access-control-one-process-per-container`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-one-process-per-container) | Each container runs one process | Yes |
| [`access-control-ssh-daemons`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-ssh-daemons) | No SSH daemons in containers | Yes |
| [`access-control-sys-nice-realtime-capability`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#access-control-sys-nice-realtime-capability) | RT kernel pods have SYS_NICE capability | Yes |

### affiliated-certification

| Check Name | Description | Covered by UT |
|---|---|---|
| [`affiliated-certification-container-is-certified-digest`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#container-is-certified-digest) | Containers passed Red Hat Container Certification | Yes |
| [`affiliated-certification-helm-version`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#helm-version) | Helm charts use v3 | Yes |
| [`affiliated-certification-helmchart-is-certified`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#helmchart-is-certified) | Helm charts passed Red Hat Helm Certification | Yes |
| [`affiliated-certification-operator-is-certified`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-is-certified) | Operators passed Red Hat Operator Certification | Yes |

### lifecycle

| Check Name | Description | Covered by UT |
|---|---|---|
| [`lifecycle-startup-probe`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-startup-probe) | Containers have startupProbe | Yes |
| [`lifecycle-readiness-probe`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-readiness-probe) | Containers have readinessProbe | Yes |
| [`lifecycle-liveness-probe`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-liveness-probe) | Containers have livenessProbe | Yes |
| [`lifecycle-container-prestop`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-container-prestop) | Containers have preStop hook | Yes |
| [`lifecycle-container-poststart`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-container-poststart) | Containers have postStart hook | Yes |
| [`lifecycle-image-pull-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-image-pull-policy) | imagePullPolicy is Always or uses digest | Yes |
| [`lifecycle-pod-owner-type`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-owner-type) | Pods owned by ReplicaSet/StatefulSet/DaemonSet | Yes |
| [`lifecycle-pod-scheduling`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-scheduling) | Pods have scheduling directives | Yes |
| [`lifecycle-pod-high-availability`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-high-availability) | Deployments have replicas > 1 | Yes |
| [`lifecycle-cpu-isolation`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-cpu-isolation) | CPU requests equal CPU limits | Yes |
| [`lifecycle-crd-scaling`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-crd-scaling) | CRD supports scale in/out operations | Yes |
| [`lifecycle-deployment-scaling`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-deployment-scaling) | Deployments support scale in/out operations | Yes |
| [`lifecycle-affinity-required-pods`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-affinity-required-pods) | Pods have anti-affinity rules | Yes |
| [`lifecycle-pod-toleration-bypass`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-toleration-bypass) | No unnecessary master taint tolerations | Yes |
| [`lifecycle-persistent-volume-reclaim-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-persistent-volume-reclaim-policy) | PV reclaimPolicy is not Delete | Yes |
| [`lifecycle-pod-recreation`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-pod-recreation) | Pods are recreated after node drain/reboot | Yes |
| [`lifecycle-statefulset-scaling`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-statefulset-scaling) | StatefulSets support scale in/out operations | Yes |
| [`lifecycle-storage-provisioner`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-storage-provisioner) | StorageClass has valid provisioner | Yes |
| [`lifecycle-topology-spread-constraint`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#lifecycle-topology-spread-constraint) | TopologySpreadConstraints cover hostname and zone | Yes |

### networking

| Check Name | Description | Covered by UT |
|---|---|---|
| [`networking-dual-stack-service`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-dual-stack-service) | Services support dual-stack | Yes |
| [`networking-icmpv4-connectivity`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#icmpv4-connectivity) | Containers can communicate via ICMPv4 | Yes |
| [`networking-icmpv4-connectivity-multus`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#icmpv4-connectivity-multus) | Containers can communicate via ICMPv4 on Multus networks | Yes |
| [`networking-icmpv6-connectivity`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#icmpv6-connectivity) | Containers can communicate via ICMPv6 | Yes |
| [`networking-icmpv6-connectivity-multus`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#icmpv6-connectivity-multus) | Containers can communicate via ICMPv6 on Multus networks | Yes |
| [`networking-network-attachment-definition-sriov-mtu`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#network-attachment-definition-sriov-mtu) | SR-IOV NetworkAttachmentDefinitions have correct MTU | Yes |
| [`networking-network-policy-deny-all`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-network-policy-deny-all) | Default-deny NetworkPolicy exists | Yes |
| [`networking-ocp-reserved-ports-usage`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-ocp-reserved-ports-usage) | No use of OCP reserved ports | Yes |
| [`networking-reserved-partner-ports`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-reserved-partner-ports) | No use of reserved partner ports | Yes |
| [`networking-restart-on-reboot-sriov-pod`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-restart-on-reboot-sriov-pod) | SR-IOV pods have restart label | Yes |
| [`networking-undeclared-container-ports-usage`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#networking-undeclared-container-ports-usage) | Containers do not listen on undeclared ports | Yes |

### observability

| Check Name | Description | Covered by UT |
|---|---|---|
| [`observability-compatibility-with-next-ocp-release`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#compatibility-with-next-ocp-release) | APIs are compatible with next OCP release | Yes |
| [`observability-container-logging`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#container-logging) | Containers log to stderr and stdout | Yes |
| [`observability-crd-status`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#observability-crd-status) | CRDs define status subresource | Yes |
| [`observability-pod-disruption-budget`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#observability-pod-disruption-budget) | PDBs exist for HA workloads | Yes |
| [`observability-termination-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#observability-termination-policy) | terminationMessagePolicy is FallbackToLogsOnError | Yes |

### performance

| Check Name | Description | Covered by UT |
|---|---|---|
| [`performance-cpu-pinning-no-exec-probes`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-cpu-pinning-no-exec-probes) | CPU-pinned pods avoid exec probes | Yes |
| [`performance-exclusive-cpu-pool`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-exclusive-cpu-pool) | Whole-CPU containers use Guaranteed QoS | Yes |
| [`performance-exclusive-cpu-pool-rt-scheduling-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#exclusive-cpu-pool-rt-scheduling-policy) | Exclusive CPU pool uses RT scheduling policy | Yes |
| [`performance-isolated-cpu-pool-rt-scheduling-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#isolated-cpu-pool-rt-scheduling-policy) | Isolated CPU pool uses RT scheduling policy | Yes |
| [`performance-limit-memory-allocation`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-limit-memory-allocation) | Containers have memory limits | Yes |
| [`performance-limited-use-of-exec-probes`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-limited-use-of-exec-probes) | Cluster-wide exec probe count below threshold | Yes |
| [`performance-max-resources-exec-probes`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-max-resources-exec-probes) | Exec probes have periodSeconds >= 10 | Yes |
| [`performance-rt-apps-no-exec-probes`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#performance-rt-apps-no-exec-probes) | RT containers avoid exec probes | Yes |
| [`performance-shared-cpu-pool-non-rt-scheduling-policy`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#shared-cpu-pool-non-rt-scheduling-policy) | Shared CPU pool uses non-RT scheduling policy | Yes |

### platform

| Check Name | Description | Covered by UT |
|---|---|---|
| [`platform-alteration-base-image`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#base-image) | Container base image is not altered post-startup | Yes |
| [`platform-alteration-boot-params`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-boot-params) | No non-standard kernel boot parameters | Yes |
| [`platform-alteration-cluster-operator-health`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#cluster-operator-health) | All cluster operators are healthy | Yes |
| [`platform-alteration-hugepages-1g-only`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-hugepages-1g-only) | Only 1Gi hugepages used | Yes |
| [`platform-alteration-hugepages-2m-only`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-hugepages-2m-only) | Only 2Mi hugepages used | Yes |
| [`platform-alteration-hugepages-config`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-hugepages-config) | Hugepage configuration is consistent | Yes |
| [`platform-alteration-hyperthread-enable`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#hyperthread-enable) | Baremetal workers have hyperthreading enabled | Yes |
| [`platform-alteration-is-selinux-enforcing`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-is-selinux-enforcing) | SELinux is in Enforcing mode | Yes |
| [`platform-alteration-isredhat-release`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#isredhat-release) | Container base image is Red Hat | Yes |
| [`platform-alteration-ocp-lifecycle`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#ocp-lifecycle) | Running OCP version is not end of life | Yes |
| [`platform-alteration-ocp-node-count`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-ocp-node-count) | Minimum worker node count met | Yes |
| [`platform-alteration-ocp-node-os-lifecycle`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#ocp-node-os-lifecycle) | Node OS is compatible with OCP version | Yes |
| [`platform-alteration-service-mesh-usage`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-service-mesh-usage) | Pods do not use Istio sidecars | Yes |
| [`platform-alteration-sysctl-config`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-sysctl-config) | Sysctl settings managed via MachineConfig | Yes |
| [`platform-alteration-tainted-node-kernel`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#platform-alteration-tainted-node-kernel) | Kernel is not tainted | Yes |

### operator

| Check Name | Description | Covered by UT |
|---|---|---|
| [`operator-catalogsource-bundle-count`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#catalogsource-bundle-count) | CatalogSource bundle count below threshold | Yes |
| [`operator-crd-openapi-schema`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-crd-openapi-schema) | CRDs have OpenAPI v3 schema | Yes |
| [`operator-crd-versioning`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-crd-versioning) | CRD versions follow K8s conventions | Yes |
| [`operator-install-source`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-install-source) | Operators installed via OLM | Yes |
| [`operator-install-status-no-privileges`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-install-status-no-privileges) | CSVs do not grant SCC access | Yes |
| [`operator-install-status-succeeded`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-install-status-succeeded) | CSVs report Succeeded status | Yes |
| [`operator-multiple-same-operators`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-multiple-same-operators) | No duplicate operator installations | Yes |
| [`operator-olm-skip-range`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-olm-skip-range) | CSVs have olm.skipRange annotation | Yes |
| [`operator-pods-no-hugepages`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-pods-no-hugepages) | Operator pods do not request hugepages | Yes |
| [`operator-semantic-versioning`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-semantic-versioning) | CSVs use semantic versioning | Yes |
| [`operator-single-crd-owner`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#operator-single-crd-owner) | Each CRD owned by one operator | Yes |
| [`operator-single-or-multi-namespaced-allowed-in-tenant-namespaces`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#single-or-multi-namespaced-allowed-in-tenant-namespaces) | Only single/multi namespaced operators in tenant namespaces | Yes |

### manageability

| Check Name | Description | Covered by UT |
|---|---|---|
| [`manageability-container-port-name-format`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#manageability-container-port-name-format) | Port names follow IANA conventions | Yes |
| [`manageability-containers-image-tag`](https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md#manageability-containers-image-tag) | Images use specific tag or digest | Yes |

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
    _ "github.com/redhat-best-practices-for-k8s/checks/certification"
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

- `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/apiextensions-apiserver` v0.36.2
- `github.com/operator-framework/api` v0.44.0 (for OLM ClusterServiceVersion types)
- Go 1.26.3+

## License

Apache License 2.0
