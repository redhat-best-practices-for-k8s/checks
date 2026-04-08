package accesscontrol

import "github.com/redhat-best-practices-for-k8s/checks"

// Metadata constants migrated from certsuite identifiers.

// Descriptions
const (
	AccessControlBpfCapabilityCheckDescription = `Ensures that containers do not use BPF capability. Workloads should avoid loading eBPF filters`

	AccessControlClusterRoleBindingsDescription = `Tests that a Pod does not specify ClusterRoleBindings.`

	AccessControlContainerHostPortDescription = `Verifies if containers define a hostPort.`

	AccessControlCrdRolesDescription = `If an application creates CRDs it must supply a role to access those CRDs and no other API resources/permission. This test checks that there is at least one role present in each namespaces under test that only refers to CRDs under test.`

	AccessControlIpcLockCapabilityCheckDescription = `Ensures that containers do not use IPC_LOCK capability. Workloads should avoid accessing host resources - spec.HostIpc should be false.`

	AccessControlNamespaceDescription = `Tests that all workload resources (PUTs and CRs) belong to valid namespaces. A valid namespace meets
the following conditions: (1) It was declared in the yaml config file under the targetNameSpaces
tag. (2) It does not have any of the following prefixes: default, openshift-, istio- and aspenmesh-`

	AccessControlNamespaceResourceQuotaDescription = `Checks to see if workload pods are running in namespaces that have resource quotas applied.`

	AccessControlNetAdminCapabilityCheckDescription = `Ensures that containers do not use NET_ADMIN capability. Note: this test also ensures iptables and nftables are not configured by workload pods:
- NET_ADMIN and NET_RAW are required to modify nftables (namespaced) which is not desired inside pods.
nftables should be configured by an administrator outside the scope of the workload. nftables are usually configured
by operators, for instance the Performance Addon Operator (PAO) or istio.
- Privileged container are required to modify host iptables, which is not safe to perform inside pods. nftables
should be configured by an administrator outside the scope of the workload. iptables are usually configured by operators,
for instance the Performance Addon Operator (PAO) or istio.`

	AccessControlNetRawCapabilityCheckDescription = `Ensures that containers do not use NET_RAW capability. Note: this test also ensures iptables and nftables are not configured by workload pods:
- NET_ADMIN and NET_RAW are required to modify nftables (namespaced) which is not desired inside pods.
nftables should be configured by an administrator outside the scope of the workload. nftables are usually configured
by operators, for instance the Performance Addon Operator (PAO) or istio.
- Privileged container are required to modify host iptables, which is not safe to perform inside pods. nftables
should be configured by an administrator outside the scope of the workload. iptables are usually configured by operators,
for instance the Performance Addon Operator (PAO) or istio.`

	AccessControlNo1337UidDescription = `Checks that all pods are not using the securityContext UID 1337`

	AccessControlOneProcessPerContainerDescription = `Check that all containers under test have only one process running`

	AccessControlPodAutomountServiceAccountTokenDescription = `Check that all pods under test have automountServiceAccountToken set to false. Only pods that require access to the kubernetes API server should have automountServiceAccountToken set to true`

	AccessControlPodHostIpcDescription = `Verifies that the spec.HostIpc parameter is set to false`

	AccessControlPodHostNetworkDescription = `Verifies that the spec.HostNetwork parameter is not set (not present)`

	AccessControlPodHostPathDescription = `Verifies that the spec.HostPath parameter is not set (not present)`

	AccessControlPodHostPidDescription = `Verifies that the spec.HostPid parameter is set to false`

	AccessControlPodRoleBindingsDescription = `Ensures that a workload does not utilize RoleBinding(s) in a non-workload Namespace.`

	AccessControlPodServiceAccountDescription = `Tests that each workload Pod utilizes a valid Service Account. Default or empty service account is not valid.`

	AccessControlRequestsDescription = `Check that containers have resource requests specified in their spec. Set proper resource requests based on container use case.`

	AccessControlSecurityContextDescription = `Checks the security context matches one of the 4 categories`

	AccessControlSecurityContextNonRootUserIdCheckDescription = `Checks securityContext's runAsNonRoot and runAsUser fields at pod and container level to make sure containers are not run as root.`

	AccessControlSecurityContextPrivilegeEscalationDescription = `Checks if privileged escalation is enabled (AllowPrivilegeEscalation=true).`

	AccessControlSecurityContextReadOnlyFileSystemDescription = `Checks the security context readOnlyFileSystem in containers is enabled. Containers should not try modify its own filesystem.`

	AccessControlServiceTypeDescription = `Tests that each workload Service does not utilize NodePort(s).`

	AccessControlSshDaemonsDescription = `Check that pods do not run SSH daemons.`

	AccessControlSysAdminCapabilityCheckDescription = `Ensures that containers do not use SYS_ADMIN capability`

	AccessControlSysNiceRealtimeCapabilityDescription = `Check that pods running on nodes with realtime kernel enabled have the SYS_NICE capability enabled in their spec. In the case that a workolad is running on a node using the real-time kernel, SYS_NICE will be used to allow DPDK application to switch to SCHED_FIFO.`

	AccessControlSysPtraceCapabilityDescription = `Check that if process namespace sharing is enabled for a Pod then the SYS_PTRACE capability is allowed. This capability is required when using Process Namespace Sharing. This is used when processes from one Container need to be exposed to another Container. For example, to send signals like SIGHUP from a process in a Container to another process in another Container. For more information on these capabilities refer to https://cloud.redhat.com/blog/linux-capabilities-in-openshift and https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/`

)

// Remediations
const (
	AccessControlBpfCapabilityCheckRemediation = `Remove the following capability from the container/pod definitions: BPF`

	AccessControlClusterRoleBindingsRemediation = `In most cases, Pod's should not have ClusterRoleBindings. The suggested remediation is to remove the need for ClusterRoleBindings, if possible. Cluster roles and cluster role bindings discouraged unless absolutely needed by the workload (often reserved for cluster admin only).`

	AccessControlContainerHostPortRemediation = `Remove hostPort configuration from the container. Workloads should avoid accessing host resources - containers should not configure HostPort.`

	AccessControlCrdRolesRemediation = `Roles providing access to CRDs should not refer to any other api or resources. Change the generation of the CRD role accordingly`

	AccessControlIpcLockCapabilityCheckRemediation = `Exception possible if a workload uses mlock(), mlockall(), shmctl(), mmap(); exception will be considered for DPDK applications. Must identify which container requires the capability and detail why.`

	AccessControlNamespaceRemediation = `Ensure that your workload utilizes namespaces declared in the yaml config file. Additionally, the namespaces should not start with "default, openshift-, istio- or aspenmesh-".`

	AccessControlNamespaceResourceQuotaRemediation = `Apply a ResourceQuota to the namespace your workload is running in. The workload's namespace should have resource quota defined.`

	AccessControlNetAdminCapabilityCheckRemediation = `Exception possible if a workload uses mlock(), mlockall(), shmctl(), mmap(); exception will be considered for DPDK applications. Must identify which container requires the capability and detail why.`

	AccessControlNetRawCapabilityCheckRemediation = `Exception possible if a workload uses mlock(), mlockall(), shmctl(), mmap(); exception will be considered for DPDK applications. Must identify which container requires the capability and detail why.`

	AccessControlNo1337UidRemediation = `Use another process UID that is not 1337.`

	AccessControlOneProcessPerContainerRemediation = `Launch only one process per container. Should adhere to 1 process per container best practice wherever possible.`

	AccessControlPodAutomountServiceAccountTokenRemediation = `Check that pod has automountServiceAccountToken set to false or pod is attached to service account which has automountServiceAccountToken set to false, unless the pod needs access to the kubernetes API server. Pods which do not need API access should set automountServiceAccountToken to false in pod spec.`

	AccessControlPodHostIpcRemediation = `Set the spec.HostIpc parameter to false in the pod configuration. Workloads should avoid accessing host resources - spec.HostIpc should be false.`

	AccessControlPodHostNetworkRemediation = `Set the spec.HostNetwork parameter to false in the pod configuration. Workloads should avoid accessing host resources - spec.HostNetwork should be false.`

	AccessControlPodHostPathRemediation = `Set the spec.HostPath parameter to false in the pod configuration. Workloads should avoid accessing host resources - spec.HostPath should be false.`

	AccessControlPodHostPidRemediation = `Set the spec.HostPid parameter to false in the pod configuration. Workloads should avoid accessing host resources - spec.HostPid should be false.`

	AccessControlPodRoleBindingsRemediation = `Ensure the workload is not configured to use RoleBinding(s) in a non-workload Namespace. Scope of role must <= scope of creator of role.`

	AccessControlPodServiceAccountRemediation = `Ensure that the each workload Pod is configured to use a valid Service Account`

	AccessControlRequestsRemediation = `Add requests to your container spec. See: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits`

	AccessControlSecurityContextRemediation = `Exception possible if a workload uses mlock(), mlockall(), shmctl(), mmap(); exception will be considered for DPDK applications. Must identify which container requires the capability and document why. If the container had the right configuration of the allowed category from the 4 approved list then the test will pass. The 4 categories are defined in [Requirement ID 94118](#security-context-categories)`

	AccessControlSecurityContextNonRootUserIdCheckRemediation = `Set the securityContext.runAsNonRoot field to true either at pod or container level. Alternatively, set a non-zero value to securityContext.runAsUser field either at pod or container level.`

	AccessControlSecurityContextPrivilegeEscalationRemediation = `Configure privilege escalation to false. Privileged escalation should not be allowed (AllowPrivilegeEscalation=false).`

	AccessControlSecurityContextReadOnlyFileSystemRemediation = `No exceptions - will only be considered under special circumstances. Must identify which container needs access and document why with details.`

	AccessControlServiceTypeRemediation = `Ensure Services are not configured to use NodePort(s). Workloads should avoid accessing host resources - tests that each workload Service does not utilize NodePort(s).`

	AccessControlSshDaemonsRemediation = `Ensure that no SSH daemons are running inside a pod. Pods should not run as SSH Daemons (replicaset or statefulset only).`

	AccessControlSysAdminCapabilityCheckRemediation = `Exception possible if a workload uses mlock(), mlockall(), shmctl(), mmap(); exception will be considered for DPDK applications. Must identify which container requires the capability and detail why. Containers should not use the SYS_ADMIN Linux capability.`

	AccessControlSysNiceRealtimeCapabilityRemediation = `If pods are scheduled to realtime kernel nodes, they must add SYS_NICE capability to their spec.`

	AccessControlSysPtraceCapabilityRemediation = `Allow the SYS_PTRACE capability when enabling process namespace sharing for a Pod`

)

// Best practice references
const (
	AccessControlBpfCapabilityCheckBestPracticeRef = checks.NoDocLinkTelco

	AccessControlClusterRoleBindingsBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-security-and-role-based-access-control`

	AccessControlContainerHostPortBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-avoid-accessing-resource-on-host`

	AccessControlCrdRolesBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-custom-role-to-access-application-crds`

	AccessControlIpcLockCapabilityCheckBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-ipc_lock`

	AccessControlNamespaceBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-requirements-cnf-reqs`

	AccessControlNamespaceResourceQuotaBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-memory-allocation`

	AccessControlNetAdminCapabilityCheckBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-net_admin`

	AccessControlNetRawCapabilityCheckBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-user-plane-cnfs`

	AccessControlNo1337UidBestPracticeRef = checks.NoDocLinkExtended

	AccessControlOneProcessPerContainerBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-one-process-per-container`

	AccessControlPodAutomountServiceAccountTokenBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-automount-services-for-pods`

	AccessControlPodHostIpcBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-security`

	AccessControlPodHostNetworkBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-security`

	AccessControlPodHostPathBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-security`

	AccessControlPodHostPidBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-security`

	AccessControlPodRoleBindingsBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-security-and-role-based-access-control`

	AccessControlPodServiceAccountBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-scc-permissions-for-an-application`

	AccessControlRequestsBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-requests-limits`

	AccessControlSecurityContextBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-linux-capabilities`

	AccessControlSecurityContextNonRootUserIdCheckBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-security`

	AccessControlSecurityContextPrivilegeEscalationBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-security`

	AccessControlSecurityContextReadOnlyFileSystemBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-linux-capabilities`

	AccessControlServiceTypeBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-security`

	AccessControlSshDaemonsBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-pod-interaction-and-configuration`

	AccessControlSysAdminCapabilityCheckBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-avoid-sys_admin`

	AccessControlSysNiceRealtimeCapabilityBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-sys_nice`

	AccessControlSysPtraceCapabilityBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-sys_ptrace`

)

// Exception processes
const (
	AccessControlBpfCapabilityCheckExceptionProcess = `Exception can be considered. Must identify which container requires the capability and detail why.`

	AccessControlClusterRoleBindingsExceptionProcess = `Exception possible only for workloads that's cluster wide in nature and absolutely needs cluster level roles & role bindings`

	AccessControlContainerHostPortExceptionProcess = `Exception for host resource access tests will only be considered in rare cases where it is absolutely needed`

	AccessControlCrdRolesExceptionProcess = checks.NoExceptionProcessExtended

	AccessControlIpcLockCapabilityCheckExceptionProcess = `Exception possible if a workload uses mlock(), mlockall(), shmctl(), mmap(); exception will be considered for DPDK applications. Must identify which container requires the capability and detail why.`

	AccessControlNamespaceExceptionProcess = checks.NoExceptions

	AccessControlNamespaceResourceQuotaExceptionProcess = checks.NoExceptionProcessExtended

	AccessControlNetAdminCapabilityCheckExceptionProcess = `Exception will be considered for user plane or networking functions (e.g. SR-IOV, Multicast). Must identify which container requires the capability and detail why.`

	AccessControlNetRawCapabilityCheckExceptionProcess = `Exception will be considered for user plane or networking functions. Must identify which container requires the capability and detail why.`

	AccessControlNo1337UidExceptionProcess = checks.NoExceptionProcessExtended

	AccessControlOneProcessPerContainerExceptionProcess = `No exception needed for optional/extended tests. Not applicable to SNO applications.`

	AccessControlPodAutomountServiceAccountTokenExceptionProcess = `Exception will be considered if container needs to access APIs which OCP does not offer natively. Must document which container requires which API(s) and detail why existing OCP APIs cannot be used.`

	AccessControlPodHostIpcExceptionProcess = `Exception for host resource access tests will only be considered in rare cases where it is absolutely needed`

	AccessControlPodHostNetworkExceptionProcess = `Exception for host resource access tests will only be considered in rare cases where it is absolutely needed`

	AccessControlPodHostPathExceptionProcess = `Exception for host resource access tests will only be considered in rare cases where it is absolutely needed`

	AccessControlPodHostPidExceptionProcess = `Exception for host resource access tests will only be considered in rare cases where it is absolutely needed`

	AccessControlPodRoleBindingsExceptionProcess = checks.NoExceptions

	AccessControlPodServiceAccountExceptionProcess = checks.NoExceptions

	AccessControlRequestsExceptionProcess = `Exceptions possible for platform and infrastructure containers. Must identify which container needs access and document why with details.`

	AccessControlSecurityContextExceptionProcess = `no exception needed for optional/extended test`

	AccessControlSecurityContextNonRootUserIdCheckExceptionProcess = `No exceptions - will only be considered under special circumstances. Must identify which container needs access and document why with details.`

	AccessControlSecurityContextPrivilegeEscalationExceptionProcess = checks.NoExceptions

	AccessControlSecurityContextReadOnlyFileSystemExceptionProcess = checks.NoExceptions

	AccessControlServiceTypeExceptionProcess = `Exception for host resource access tests will only be considered in rare cases where it is absolutely needed`

	AccessControlSshDaemonsExceptionProcess = `No exceptions - special consideration can be given to certain containers which run as utility tool daemon`

	AccessControlSysAdminCapabilityCheckExceptionProcess = checks.NoExceptions

	AccessControlSysNiceRealtimeCapabilityExceptionProcess = checks.NoExceptionProcess

	AccessControlSysPtraceCapabilityExceptionProcess = checks.NoExceptionProcess

)

// Impact statements
const (
	AccessControlBpfCapabilityCheckImpactStatement = `BPF capability allows kernel-level programming that can bypass security controls, monitor other processes, and potentially compromise the entire host system.`

	AccessControlClusterRoleBindingsImpactStatement = `Cluster-wide role bindings grant excessive privileges that can be exploited for lateral movement and privilege escalation across the entire cluster.`

	AccessControlContainerHostPortImpactStatement = `Host port usage can create port conflicts with host services and expose containers directly to the host network, bypassing network security controls.`

	AccessControlCrdRolesImpactStatement = `Improper CRD role configurations can grant excessive privileges, violate least-privilege principles, and create security vulnerabilities in custom resource access control.`

	AccessControlIpcLockCapabilityCheckImpactStatement = `IPC_LOCK capability can be exploited to lock system memory, potentially causing denial of service and affecting other workloads on the same node.`

	AccessControlNamespaceImpactStatement = `Using inappropriate namespaces can lead to resource conflicts, security boundary violations, and administrative complexity in multi-tenant environments.`

	AccessControlNamespaceResourceQuotaImpactStatement = `Without resource quotas, workloads can consume excessive cluster resources, causing performance issues and potential denial of service for other applications.`

	AccessControlNetAdminCapabilityCheckImpactStatement = `NET_ADMIN capability allows network configuration changes that can compromise cluster networking, enable privilege escalation, and bypass network security controls.`

	AccessControlNetRawCapabilityCheckImpactStatement = `NET_RAW capability enables packet manipulation and network sniffing, which can be used for attacks against other workloads and compromise network security.`

	AccessControlNo1337UidImpactStatement = `UID 1337 is reserved for use by Istio service mesh components; using it for applications can cause conflicts with Istio sidecars and break service mesh functionality.`

	AccessControlOneProcessPerContainerImpactStatement = `Multiple processes per container complicate monitoring, debugging, and security assessment, and can lead to zombie processes and resource leaks.`

	AccessControlPodAutomountServiceAccountTokenImpactStatement = `Auto-mounted service account tokens expose Kubernetes API credentials to application code, creating potential attack vectors if applications are compromised.`

	AccessControlPodHostIpcImpactStatement = `Host IPC access allows containers to communicate with host processes, potentially exposing sensitive information and enabling privilege escalation.`

	AccessControlPodHostNetworkImpactStatement = `Host network access removes network isolation, exposes containers to host network interfaces, and can compromise cluster networking security.`

	AccessControlPodHostPathImpactStatement = `Host path mounts can expose sensitive host files to containers, enable container escape attacks, and compromise host system integrity.`

	AccessControlPodHostPidImpactStatement = `Host PID access allows containers to see and interact with all host processes, creating opportunities for privilege escalation and information disclosure.`

	AccessControlPodRoleBindingsImpactStatement = `Cross-namespace role bindings can violate tenant isolation and create unintended privilege escalation paths.`

	AccessControlPodServiceAccountImpactStatement = `Default service accounts often have excessive privileges; improper usage can lead to unauthorized API access and security violations.`

	AccessControlRequestsImpactStatement = `Missing resource requests can lead to resource contention, node instability, and unpredictable application performance.`

	AccessControlSecurityContextImpactStatement = `Incorrect security context configurations can weaken container isolation, enable privilege escalation, and create exploitable attack vectors.`

	AccessControlSecurityContextNonRootUserIdCheckImpactStatement = `Running containers as root increases the blast radius of security vulnerabilities and can lead to full host compromise if containers are breached.`

	AccessControlSecurityContextPrivilegeEscalationImpactStatement = `Allowing privilege escalation can lead to containers gaining root access, compromising the security boundary between containers and hosts.`

	AccessControlSecurityContextReadOnlyFileSystemImpactStatement = `Writable root filesystems increase the attack surface and can be exploited to modify container behavior or persist malware.`

	AccessControlServiceTypeImpactStatement = `NodePort services expose applications directly on host ports, creating security risks and potential port conflicts with host services.`

	AccessControlSshDaemonsImpactStatement = `SSH daemons in containers create additional attack surfaces, violate immutable infrastructure principles, and can be exploited for unauthorized access.`

	AccessControlSysAdminCapabilityCheckImpactStatement = `SYS_ADMIN capability provides extensive privileges that can compromise container isolation, enable host system access, and create serious security vulnerabilities.`

	AccessControlSysNiceRealtimeCapabilityImpactStatement = `Missing SYS_NICE capability on real-time nodes prevents applications from setting appropriate scheduling priorities, causing performance degradation.`

	AccessControlSysPtraceCapabilityImpactStatement = `Missing SYS_PTRACE capability when using shared process namespaces prevents inter-container process communication, breaking application functionality.`

)
