package accesscontrol

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "access-control-bpf-capability-check",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-bpf-capability-check",
			Fn:       CheckBPF,
			Description: AccessControlBpfCapabilityCheckDescription,
			Remediation: AccessControlBpfCapabilityCheckRemediation,
			BestPracticeReference: AccessControlBpfCapabilityCheckBestPracticeRef,
			ExceptionProcess: AccessControlBpfCapabilityCheckExceptionProcess,
			ImpactStatement: AccessControlBpfCapabilityCheckImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-cluster-role-bindings",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-cluster-role-bindings",
			Fn:       CheckClusterRoleBindings,
			Description: AccessControlClusterRoleBindingsDescription,
			Remediation: AccessControlClusterRoleBindingsRemediation,
			BestPracticeReference: AccessControlClusterRoleBindingsBestPracticeRef,
			ExceptionProcess: AccessControlClusterRoleBindingsExceptionProcess,
			ImpactStatement: AccessControlClusterRoleBindingsImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-container-host-port",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-container-host-port",
			Fn:       CheckContainerHostPort,
			Description: AccessControlContainerHostPortDescription,
			Remediation: AccessControlContainerHostPortRemediation,
			BestPracticeReference: AccessControlContainerHostPortBestPracticeRef,
			ExceptionProcess: AccessControlContainerHostPortExceptionProcess,
			ImpactStatement: AccessControlContainerHostPortImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-crd-roles",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-crd-roles",
			Fn:       CheckCrdRoles,
			Description: AccessControlCrdRolesDescription,
			Remediation: AccessControlCrdRolesRemediation,
			BestPracticeReference: AccessControlCrdRolesBestPracticeRef,
			ExceptionProcess: AccessControlCrdRolesExceptionProcess,
			ImpactStatement: AccessControlCrdRolesImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-ipc-lock-capability-check",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-ipc-lock-capability-check",
			Fn:       CheckIPCLock,
			Description: AccessControlIpcLockCapabilityCheckDescription,
			Remediation: AccessControlIpcLockCapabilityCheckRemediation,
			BestPracticeReference: AccessControlIpcLockCapabilityCheckBestPracticeRef,
			ExceptionProcess: AccessControlIpcLockCapabilityCheckExceptionProcess,
			ImpactStatement: AccessControlIpcLockCapabilityCheckImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-namespace",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-namespace",
			Fn:       CheckNamespace,
			Description: AccessControlNamespaceDescription,
			Remediation: AccessControlNamespaceRemediation,
			BestPracticeReference: AccessControlNamespaceBestPracticeRef,
			ExceptionProcess: AccessControlNamespaceExceptionProcess,
			ImpactStatement: AccessControlNamespaceImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-namespace-resource-quota",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-namespace-resource-quota",
			Fn:       CheckNamespaceResourceQuota,
			Description: AccessControlNamespaceResourceQuotaDescription,
			Remediation: AccessControlNamespaceResourceQuotaRemediation,
			BestPracticeReference: AccessControlNamespaceResourceQuotaBestPracticeRef,
			ExceptionProcess: AccessControlNamespaceResourceQuotaExceptionProcess,
			ImpactStatement: AccessControlNamespaceResourceQuotaImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-net-admin-capability-check",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-net-admin-capability-check",
			Fn:       CheckNetAdmin,
			Description: AccessControlNetAdminCapabilityCheckDescription,
			Remediation: AccessControlNetAdminCapabilityCheckRemediation,
			BestPracticeReference: AccessControlNetAdminCapabilityCheckBestPracticeRef,
			ExceptionProcess: AccessControlNetAdminCapabilityCheckExceptionProcess,
			ImpactStatement: AccessControlNetAdminCapabilityCheckImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-net-raw-capability-check",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-net-raw-capability-check",
			Fn:       CheckNetRaw,
			Description: AccessControlNetRawCapabilityCheckDescription,
			Remediation: AccessControlNetRawCapabilityCheckRemediation,
			BestPracticeReference: AccessControlNetRawCapabilityCheckBestPracticeRef,
			ExceptionProcess: AccessControlNetRawCapabilityCheckExceptionProcess,
			ImpactStatement: AccessControlNetRawCapabilityCheckImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-no-1337-uid",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-no-1337-uid",
			Fn:       Check1337UID,
			Description: AccessControlNo1337UidDescription,
			Remediation: AccessControlNo1337UidRemediation,
			BestPracticeReference: AccessControlNo1337UidBestPracticeRef,
			ExceptionProcess: AccessControlNo1337UidExceptionProcess,
			ImpactStatement: AccessControlNo1337UidImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-one-process-per-container",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-one-process-per-container",
			Fn:       CheckOneProcess,
			Description: AccessControlOneProcessPerContainerDescription,
			Remediation: AccessControlOneProcessPerContainerRemediation,
			BestPracticeReference: AccessControlOneProcessPerContainerBestPracticeRef,
			ExceptionProcess: AccessControlOneProcessPerContainerExceptionProcess,
			ImpactStatement: AccessControlOneProcessPerContainerImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-pod-automount-service-account-token",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-pod-automount-service-account-token",
			Fn:       CheckAutomountToken,
			Description: AccessControlPodAutomountServiceAccountTokenDescription,
			Remediation: AccessControlPodAutomountServiceAccountTokenRemediation,
			BestPracticeReference: AccessControlPodAutomountServiceAccountTokenBestPracticeRef,
			ExceptionProcess: AccessControlPodAutomountServiceAccountTokenExceptionProcess,
			ImpactStatement: AccessControlPodAutomountServiceAccountTokenImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-pod-host-ipc",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-pod-host-ipc",
			Fn:       CheckHostIPC,
			Description: AccessControlPodHostIpcDescription,
			Remediation: AccessControlPodHostIpcRemediation,
			BestPracticeReference: AccessControlPodHostIpcBestPracticeRef,
			ExceptionProcess: AccessControlPodHostIpcExceptionProcess,
			ImpactStatement: AccessControlPodHostIpcImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-pod-host-network",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-pod-host-network",
			Fn:       CheckHostNetwork,
			Description: AccessControlPodHostNetworkDescription,
			Remediation: AccessControlPodHostNetworkRemediation,
			BestPracticeReference: AccessControlPodHostNetworkBestPracticeRef,
			ExceptionProcess: AccessControlPodHostNetworkExceptionProcess,
			ImpactStatement: AccessControlPodHostNetworkImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-pod-host-path",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-pod-host-path",
			Fn:       CheckHostPath,
			Description: AccessControlPodHostPathDescription,
			Remediation: AccessControlPodHostPathRemediation,
			BestPracticeReference: AccessControlPodHostPathBestPracticeRef,
			ExceptionProcess: AccessControlPodHostPathExceptionProcess,
			ImpactStatement: AccessControlPodHostPathImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-pod-host-pid",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-pod-host-pid",
			Fn:       CheckHostPID,
			Description: AccessControlPodHostPidDescription,
			Remediation: AccessControlPodHostPidRemediation,
			BestPracticeReference: AccessControlPodHostPidBestPracticeRef,
			ExceptionProcess: AccessControlPodHostPidExceptionProcess,
			ImpactStatement: AccessControlPodHostPidImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-pod-role-bindings",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-pod-role-bindings",
			Fn:       CheckRoleBindings,
			Description: AccessControlPodRoleBindingsDescription,
			Remediation: AccessControlPodRoleBindingsRemediation,
			BestPracticeReference: AccessControlPodRoleBindingsBestPracticeRef,
			ExceptionProcess: AccessControlPodRoleBindingsExceptionProcess,
			ImpactStatement: AccessControlPodRoleBindingsImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-pod-service-account",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-pod-service-account",
			Fn:       CheckServiceAccount,
			Description: AccessControlPodServiceAccountDescription,
			Remediation: AccessControlPodServiceAccountRemediation,
			BestPracticeReference: AccessControlPodServiceAccountBestPracticeRef,
			ExceptionProcess: AccessControlPodServiceAccountExceptionProcess,
			ImpactStatement: AccessControlPodServiceAccountImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-requests",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-requests",
			Fn:       CheckPodRequests,
			Description: AccessControlRequestsDescription,
			Remediation: AccessControlRequestsRemediation,
			BestPracticeReference: AccessControlRequestsBestPracticeRef,
			ExceptionProcess: AccessControlRequestsExceptionProcess,
			ImpactStatement: AccessControlRequestsImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-security-context",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-security-context",
			Fn:       CheckSecurityContext,
			Description: AccessControlSecurityContextDescription,
			Remediation: AccessControlSecurityContextRemediation,
			BestPracticeReference: AccessControlSecurityContextBestPracticeRef,
			ExceptionProcess: AccessControlSecurityContextExceptionProcess,
			ImpactStatement: AccessControlSecurityContextImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-security-context-non-root-user-id-check",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-security-context-non-root-user-id-check",
			Fn:       CheckNonRootUser,
			Description: AccessControlSecurityContextNonRootUserIdCheckDescription,
			Remediation: AccessControlSecurityContextNonRootUserIdCheckRemediation,
			BestPracticeReference: AccessControlSecurityContextNonRootUserIdCheckBestPracticeRef,
			ExceptionProcess: AccessControlSecurityContextNonRootUserIdCheckExceptionProcess,
			ImpactStatement: AccessControlSecurityContextNonRootUserIdCheckImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-security-context-privilege-escalation",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-security-context-privilege-escalation",
			Fn:       CheckPrivilegeEscalation,
			Description: AccessControlSecurityContextPrivilegeEscalationDescription,
			Remediation: AccessControlSecurityContextPrivilegeEscalationRemediation,
			BestPracticeReference: AccessControlSecurityContextPrivilegeEscalationBestPracticeRef,
			ExceptionProcess: AccessControlSecurityContextPrivilegeEscalationExceptionProcess,
			ImpactStatement: AccessControlSecurityContextPrivilegeEscalationImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-security-context-read-only-file-system",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-security-context-read-only-file-system",
			Fn:       CheckReadOnlyFilesystem,
			Description: AccessControlSecurityContextReadOnlyFileSystemDescription,
			Remediation: AccessControlSecurityContextReadOnlyFileSystemRemediation,
			BestPracticeReference: AccessControlSecurityContextReadOnlyFileSystemBestPracticeRef,
			ExceptionProcess: AccessControlSecurityContextReadOnlyFileSystemExceptionProcess,
			ImpactStatement: AccessControlSecurityContextReadOnlyFileSystemImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-service-type",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-service-type",
			Fn:       CheckNodePortService,
			Description: AccessControlServiceTypeDescription,
			Remediation: AccessControlServiceTypeRemediation,
			BestPracticeReference: AccessControlServiceTypeBestPracticeRef,
			ExceptionProcess: AccessControlServiceTypeExceptionProcess,
			ImpactStatement: AccessControlServiceTypeImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-ssh-daemons",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-ssh-daemons",
			Fn:       CheckNoSSHD,
			Description: AccessControlSshDaemonsDescription,
			Remediation: AccessControlSshDaemonsRemediation,
			BestPracticeReference: AccessControlSshDaemonsBestPracticeRef,
			ExceptionProcess: AccessControlSshDaemonsExceptionProcess,
			ImpactStatement: AccessControlSshDaemonsImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-sys-admin-capability-check",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-sys-admin-capability-check",
			Fn:       CheckSysAdmin,
			Description: AccessControlSysAdminCapabilityCheckDescription,
			Remediation: AccessControlSysAdminCapabilityCheckRemediation,
			BestPracticeReference: AccessControlSysAdminCapabilityCheckBestPracticeRef,
			ExceptionProcess: AccessControlSysAdminCapabilityCheckExceptionProcess,
			ImpactStatement: AccessControlSysAdminCapabilityCheckImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-sys-nice-realtime-capability",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-sys-nice-realtime-capability",
			Fn:       CheckSysNiceRealtime,
			Description: AccessControlSysNiceRealtimeCapabilityDescription,
			Remediation: AccessControlSysNiceRealtimeCapabilityRemediation,
			BestPracticeReference: AccessControlSysNiceRealtimeCapabilityBestPracticeRef,
			ExceptionProcess: AccessControlSysNiceRealtimeCapabilityExceptionProcess,
			ImpactStatement: AccessControlSysNiceRealtimeCapabilityImpactStatement,
			Qe: false,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "access-control-sys-ptrace-capability",
			Category: checks.CategoryAccessControl,
			CatalogID: "access-control-sys-ptrace-capability",
			Fn:       CheckSysPtrace,
			Description: AccessControlSysPtraceCapabilityDescription,
			Remediation: AccessControlSysPtraceCapabilityRemediation,
			BestPracticeReference: AccessControlSysPtraceCapabilityBestPracticeRef,
			ExceptionProcess: AccessControlSysPtraceCapabilityExceptionProcess,
			ImpactStatement: AccessControlSysPtraceCapabilityImpactStatement,
			Qe: true,
			Tags: []string{checks.TagTelco},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})
	})
}
