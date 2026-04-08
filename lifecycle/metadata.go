package lifecycle

import "github.com/redhat-best-practices-for-k8s/checks"

// Metadata constants migrated from certsuite identifiers.

// Descriptions
const (
	LifecycleAffinityRequiredPodsDescription = `Checks that affinity rules are in place if AffinityRequired: 'true' labels are set on Pods.`

	LifecycleContainerPoststartDescription = `Ensure that the containers lifecycle postStart management feature is configured. A container must receive important events from the platform and conform/react to these events properly. For example, a container should catch SIGTERM or SIGKILL from the platform and shutdown as quickly as possible. Other typically important events from the platform are PostStart to initialize before servicing requests and PreStop to release resources cleanly before shutting down.`

	LifecycleContainerPrestopDescription = `Ensure that the containers lifecycle preStop management feature is configured. The most basic requirement for the lifecycle management of Pods in OpenShift are the ability to start and stop correctly. There are different ways a pod can stop on an OpenShift cluster. One way is that the pod can remain alive but non-functional. Another way is that the pod can crash and become non-functional. When pods are shut down by the platform they are sent a SIGTERM signal which means that the process in the container should start shutting down, closing connections and stopping all activity. If the pod doesn’t shut down within the default 30 seconds then the platform may send a SIGKILL signal which will stop the pod immediately. This method isn’t as clean and the default time between the SIGTERM and SIGKILL messages can be modified based on the requirements of the application. Containers should respond to SIGTERM/SIGKILL with graceful shutdown.`

	LifecycleCpuIsolationDescription = `CPU isolation requires: For each container within the pod, resource requests and limits must be identical. If cpu requests and limits are not identical and in whole units (Guaranteed pods with exclusive cpus), your pods will not be tested for compliance. The runTimeClassName must be specified. Annotations required disabling CPU and IRQ load-balancing.`

	LifecycleCrdScalingDescription = `Tests that a workload's CRD support scale in/out operations. First, the test starts getting the current replicaCount (N) of the crd/s with the Pod Under Test. Then, it executes the scale-in oc command for (N-1) replicas. Lastly, it executes the scale-out oc command, restoring the original replicaCount of the crd/s. In case of crd that are managed by HPA the test is changing the min and max value to crd Replica - 1 during scale-in and the original replicaCount again for both min/max during the scale-out stage. Lastly its restoring the original min/max replica of the crd/s`

	LifecycleDeploymentScalingDescription = `Tests that workload deployments support scale in/out operations. First, the test starts getting the current replicaCount (N) of the deployment/s with the Pod Under Test. Then, it executes the scale-in oc command for (N-1) replicas. Lastly, it executes the scale-out oc command, restoring the original replicaCount of the deployment/s. In case of deployments that are managed by HPA the test is changing the min and max value to deployment Replica - 1 during scale-in and the original replicaCount again for both min/max during the scale-out stage. Lastly its restoring the original min/max replica of the deployment/s`

	LifecycleImagePullPolicyDescription = `Ensure that the containers under test are using IfNotPresent as Image Pull Policy. If there is a situation where the container dies and needs to be restarted, the image pull policy becomes important. PullIfNotPresent is recommended so that a loss of image registry access does not prevent the pod from restarting.`

	LifecycleLivenessProbeDescription = `Check that all containers under test have liveness probe defined. The most basic requirement for the lifecycle management of Pods in OpenShift are the ability to start and stop correctly. When starting up, health probes like liveness and readiness checks can be put into place to ensure the application is functioning properly.`

	LifecyclePersistentVolumeReclaimPolicyDescription = `Check that the persistent volumes the workloads pods are using have a reclaim policy of delete. Network Functions should clear persistent storage by deleting their PVs when removing their application from a cluster.`

	LifecyclePodHighAvailabilityDescription = `Ensures that workloads Pods specify podAntiAffinity rules and replica value is set to more than 1.`

	LifecyclePodOwnerTypeDescription = `Tests that the workload Pods are deployed as part of a ReplicaSet(s)/StatefulSet(s).`

	LifecyclePodRecreationDescription = `Tests that a workload is configured to support High Availability. First, this test cordons and drains a Node that hosts the workload Pod. Next, the test ensures that OpenShift can re-instantiate the Pod on another Node, and that the actual replica count matches the desired replica count.`

	LifecyclePodSchedulingDescription = `Ensures that workload Pods do not specify nodeSelector or nodeAffinity. In most cases, Pods should allow for instantiation on any underlying Node. Workloads shall not use node selectors nor taints/tolerations to assign pod location.`

	LifecyclePodTolerationBypassDescription = `Check that pods do not have NoExecute, PreferNoSchedule, or NoSchedule tolerations that have been modified from the default.`

	LifecycleReadinessProbeDescription = `Check that all containers under test have readiness probe defined. There are different ways a pod can stop on on OpenShift cluster. One way is that the pod can remain alive but non-functional. Another way is that the pod can crash and become non-functional. In the first case, if the administrator has implemented liveness and readiness checks, OpenShift can stop the pod and either restart it on the same node or a different node in the cluster. For the second case, when the application in the pod stops, it should exit with a code and write suitable log entries to help the administrator diagnose what the issue was that caused the problem.`

	LifecycleStartupProbeDescription = `Check that all containers under test have startup probe defined. Workloads shall self-recover from common failures like pod failure, host failure, and network failure. Kubernetes native mechanisms such as health-checks (Liveness, Readiness and Startup Probes) shall be employed at a minimum.`

	LifecycleStatefulsetScalingDescription = `Tests that workload statefulsets support scale in/out operations. First, the test starts getting the current replicaCount (N) of the statefulset/s with the Pod Under Test. Then, it executes the scale-in oc command for (N-1) replicas. Lastly, it executes the scale-out oc command, restoring the original replicaCount of the statefulset/s. In case of statefulsets that are managed by HPA the test is changing the min and max value to statefulset Replica - 1 during scale-in and the original replicaCount again for both min/max during the scale-out stage. Lastly its restoring the original min/max replica of the statefulset/s`

	LifecycleStorageProvisionerDescription = `Checks that pods do not place persistent volumes on local storage in multinode clusters. Local storage is recommended for single node clusters, but only one type of local storage should be installed (lvms or noprovisioner).`

	LifecycleTopologySpreadConstraintDescription = `Ensures that Deployments using TopologySpreadConstraints include constraints for both hostname and zone topology keys. This helps telco workloads avoid needing to tweak PodDisruptionBudgets before platform upgrades. If TopologySpreadConstraints is not defined, the test passes as Kubernetes scheduler implicitly uses hostname and zone constraints. Not applicable to SNO applications.`

)

// Remediations
const (
	LifecycleAffinityRequiredPodsRemediation = `Pods which need to be co-located on the same node need Affinity rules. If a pod/statefulset/deployment is required to use affinity rules, please add AffinityRequired: 'true' as a label.`

	LifecycleContainerPoststartRemediation = `PostStart is normally used to configure the container, set up dependencies, and record the new creation. You could use this event to check that a required API is available before the container’s main work begins. Kubernetes will not change the container’s state to Running until the PostStart script has executed successfully. For details, see https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks. PostStart is used to configure container, set up dependencies, record new creation. It can also be used to check that a required API is available before the container’s work begins.`

	LifecycleContainerPrestopRemediation = `The preStop can be used to gracefully stop the container and clean resources (e.g., DB connection). For details, see https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks. All pods must respond to SIGTERM signal and shutdown gracefully with a zero exit code.`

	LifecycleCpuIsolationRemediation = `CPU isolation testing is enabled. Please ensure that all pods adhere to the CPU isolation requirements.`

	LifecycleCrdScalingRemediation = `Ensure the workload's CRDs can scale in/out successfully.`

	LifecycleDeploymentScalingRemediation = `Ensure the workload's deployments/replica sets can scale in/out successfully.`

	LifecycleImagePullPolicyRemediation = `Ensure that the containers under test are using IfNotPresent as Image Pull Policy.`

	LifecycleLivenessProbeRemediation = `Add a liveness probe to deployed containers. workloads shall self-recover from common failures like pod failure, host failure, and network failure. Kubernetes native mechanisms such as health-checks (Liveness, Readiness and Startup Probes) shall be employed at a minimum.`

	LifecyclePersistentVolumeReclaimPolicyRemediation = `Ensure that all persistent volumes are using the reclaim policy: delete`

	LifecyclePodHighAvailabilityRemediation = `In high availability cases, Pod podAntiAffinity rule should be specified for pod scheduling and pod replica value is set to more than 1 .`

	LifecyclePodOwnerTypeRemediation = `Deploy the workload using ReplicaSet/StatefulSet.`

	LifecyclePodRecreationRemediation = `Ensure that the workloads Pods utilize a configuration that supports High Availability. Additionally, ensure that there are available Nodes in the OpenShift cluster that can be utilized in the event that a host Node fails.`

	LifecyclePodSchedulingRemediation = `In most cases, Pod's should not specify their host Nodes through nodeSelector or nodeAffinity. However, there are cases in which workloads require specialized hardware specific to a particular class of Node.`

	LifecyclePodTolerationBypassRemediation = `Do not allow pods to bypass the NoExecute, PreferNoSchedule, or NoSchedule tolerations that are default applied by Kubernetes.`

	LifecycleReadinessProbeRemediation = `Add a readiness probe to deployed containers`

	LifecycleStartupProbeRemediation = `Add a startup probe to deployed containers`

	LifecycleStatefulsetScalingRemediation = `Ensure the workload's statefulsets/replica sets can scale in/out successfully.`

	LifecycleStorageProvisionerRemediation = `Use a non-local storage (e.g. no kubernetes.io/no-provisioner and no topolvm.io provisioners) in multinode clusters. Local storage are recommended for single node clusters only, but a single local provisioner should be installed.`

	LifecycleTopologySpreadConstraintRemediation = `If using TopologySpreadConstraints in your Deployment, ensure you include constraints for both 'kubernetes.io/hostname' and 'topology.kubernetes.io/zone' topology keys. Alternatively, you can omit TopologySpreadConstraints entirely to let Kubernetes scheduler use implicit hostname and zone constraints. This helps maintain workload availability during platform upgrades without manually adjusting PodDisruptionBudgets.`

)

// Best practice references
const (
	LifecycleAffinityRequiredPodsBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-high-level-cnf-expectations`

	LifecycleContainerPoststartBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cloud-native-design-best-practices`

	LifecycleContainerPrestopBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cloud-native-design-best-practices`

	LifecycleCpuIsolationBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cpu-isolation`

	LifecycleCrdScalingBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-high-level-cnf-expectations`

	LifecycleDeploymentScalingBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-high-level-cnf-expectations`

	LifecycleImagePullPolicyBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-use-imagepullpolicy:-ifnotpresent`

	LifecycleLivenessProbeBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-liveness-readiness-and-startup-probes`

	LifecyclePersistentVolumeReclaimPolicyBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-csi`

	LifecyclePodHighAvailabilityBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-high-level-cnf-expectations`

	LifecyclePodOwnerTypeBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-no-naked-pods`

	LifecyclePodRecreationBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-upgrade-expectations`

	LifecyclePodSchedulingBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-high-level-cnf-expectations`

	LifecyclePodTolerationBypassBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cpu-manager-pinning`

	LifecycleReadinessProbeBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-liveness-readiness-and-startup-probes`

	LifecycleStartupProbeBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-liveness-readiness-and-startup-probes`

	LifecycleStatefulsetScalingBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-high-level-cnf-expectations`

	LifecycleStorageProvisionerBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-local-storage`

	LifecycleTopologySpreadConstraintBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-high-level-cnf-expectations`

)

// Exception processes
const (
	LifecycleAffinityRequiredPodsExceptionProcess = checks.NoExceptionProcess

	LifecycleContainerPoststartExceptionProcess = `Identify which pod is not conforming to the process and submit information as to why it cannot use a postStart startup specification.`

	LifecycleContainerPrestopExceptionProcess = `Identify which pod is not conforming to the process and submit information as to why it cannot use a preStop shutdown specification.`

	LifecycleCpuIsolationExceptionProcess = checks.NoExceptionProcess

	LifecycleCrdScalingExceptionProcess = `There is no documented exception process for this. Not applicable to SNO applications.`

	LifecycleDeploymentScalingExceptionProcess = `There is no documented exception process for this. Not applicable to SNO applications.`

	LifecycleImagePullPolicyExceptionProcess = checks.NoExceptionProcess

	LifecycleLivenessProbeExceptionProcess = checks.NoExceptionProcess

	LifecyclePersistentVolumeReclaimPolicyExceptionProcess = checks.NoExceptionProcess

	LifecyclePodHighAvailabilityExceptionProcess = `There is no documented exception process for this. Not applicable to SNO applications.`

	LifecyclePodOwnerTypeExceptionProcess = `There is no documented exception process for this. Pods should not be deployed as DaemonSet or naked pods.`

	LifecyclePodRecreationExceptionProcess = `No exceptions - workloads should be able to be restarted/recreated.`

	LifecyclePodSchedulingExceptionProcess = `Exception will only be considered if application requires specialized hardware. Must specify which container requires special hardware and why.`

	LifecyclePodTolerationBypassExceptionProcess = checks.NoExceptionProcess

	LifecycleReadinessProbeExceptionProcess = checks.NoExceptionProcess

	LifecycleStartupProbeExceptionProcess = checks.NoExceptionProcess

	LifecycleStatefulsetScalingExceptionProcess = `There is no documented exception process for this. Not applicable to SNO applications.`

	LifecycleStorageProvisionerExceptionProcess = checks.NoExceptions

	LifecycleTopologySpreadConstraintExceptionProcess = checks.NoExceptionProcess

)

// Impact statements
const (
	LifecycleAffinityRequiredPodsImpactStatement = `Missing affinity rules can cause incorrect pod placement, leading to performance issues and failure to meet co-location requirements.`

	LifecycleContainerPoststartImpactStatement = `Missing PostStart hooks can cause containers to start serving traffic before proper initialization, leading to application errors.`

	LifecycleContainerPrestopImpactStatement = `Missing PreStop hooks can cause ungraceful shutdowns, data loss, and connection drops during container termination.`

	LifecycleCpuIsolationImpactStatement = `Improper CPU isolation can cause performance interference between workloads and fail to provide guaranteed compute resources.`

	LifecycleCrdScalingImpactStatement = `CRD scaling failures can prevent operator-managed applications from scaling properly, limiting application availability and performance.`

	LifecycleDeploymentScalingImpactStatement = `Deployment scaling failures prevent horizontal scaling operations, limiting application elasticity and availability during high load.`

	LifecycleImagePullPolicyImpactStatement = `Incorrect image pull policies can cause deployment failures when image registries are unavailable or during network issues.`

	LifecycleLivenessProbeImpactStatement = `Missing liveness probes prevent Kubernetes from detecting and recovering from application deadlocks and hangs.`

	LifecyclePersistentVolumeReclaimPolicyImpactStatement = `Incorrect reclaim policies can lead to data persistence after application removal, causing storage waste and potential data security issues.`

	LifecyclePodHighAvailabilityImpactStatement = `Missing anti-affinity rules can cause all pod replicas to be scheduled on the same node, creating single points of failure.`

	LifecyclePodOwnerTypeImpactStatement = `Naked pods and DaemonSets lack proper lifecycle management, making updates, scaling, and recovery operations difficult or impossible.`

	LifecyclePodRecreationImpactStatement = `Failed pod recreation indicates poor high availability configuration, leading to potential service outages during node failures.`

	LifecyclePodSchedulingImpactStatement = `Node selectors can create scheduling constraints that reduce cluster flexibility and cause deployment failures when nodes are unavailable.`

	LifecyclePodTolerationBypassImpactStatement = `Modified tolerations can allow pods to be scheduled on inappropriate nodes, violating scheduling policies and causing performance issues.`

	LifecycleReadinessProbeImpactStatement = `Missing readiness probes can cause traffic to be routed to non-ready pods, resulting in failed requests and poor user experience.`

	LifecycleStartupProbeImpactStatement = `Missing startup probes can cause slow-starting applications to be killed prematurely, preventing successful application startup.`

	LifecycleStatefulsetScalingImpactStatement = `StatefulSet scaling issues can prevent proper data persistence and ordered deployment of stateful applications.`

	LifecycleStorageProvisionerImpactStatement = `Inappropriate storage provisioners can cause data persistence issues, performance problems, and storage failures.`

	LifecycleTopologySpreadConstraintImpactStatement = `Without proper topology spread constraints, pods may cluster on nodes causing PodDisruptionBudgets to block platform upgrades, requiring manual PDB adjustments and increasing operational complexity during maintenance windows.`

)
