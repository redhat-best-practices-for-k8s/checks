package networking

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "networking-dual-stack-service",
			Category: checks.CategoryNetworking,
			CatalogID: "networking-dual-stack-service",
			Fn:       CheckDualStackService,
			Description: NetworkingDualStackServiceDescription,
			Remediation: NetworkingDualStackServiceRemediation,
			BestPracticeReference: NetworkingDualStackServiceBestPracticeRef,
			ExceptionProcess: NetworkingDualStackServiceExceptionProcess,
			ImpactStatement: NetworkingDualStackServiceImpactStatement,
			Qe: false,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "networking-icmpv4-connectivity",
			Category: checks.CategoryNetworking,
			CatalogID: "icmpv4-connectivity",
			Fn:       CheckICMPv4Connectivity,
			Description: NetworkingIcmpv4ConnectivityDescription,
			Remediation: NetworkingIcmpv4ConnectivityRemediation,
			BestPracticeReference: NetworkingIcmpv4ConnectivityBestPracticeRef,
			ExceptionProcess: NetworkingIcmpv4ConnectivityExceptionProcess,
			ImpactStatement: NetworkingIcmpv4ConnectivityImpactStatement,
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
			Name:     "networking-icmpv4-connectivity-multus",
			Category: checks.CategoryNetworking,
			CatalogID: "icmpv4-connectivity-multus",
			Fn:       CheckICMPv4ConnectivityMultus,
			Description: NetworkingIcmpv4ConnectivityMultusDescription,
			Remediation: NetworkingIcmpv4ConnectivityMultusRemediation,
			BestPracticeReference: NetworkingIcmpv4ConnectivityMultusBestPracticeRef,
			ExceptionProcess: NetworkingIcmpv4ConnectivityMultusExceptionProcess,
			ImpactStatement: NetworkingIcmpv4ConnectivityMultusImpactStatement,
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
			Name:     "networking-icmpv6-connectivity",
			Category: checks.CategoryNetworking,
			CatalogID: "icmpv6-connectivity",
			Fn:       CheckICMPv6Connectivity,
			Description: NetworkingIcmpv6ConnectivityDescription,
			Remediation: NetworkingIcmpv6ConnectivityRemediation,
			BestPracticeReference: NetworkingIcmpv6ConnectivityBestPracticeRef,
			ExceptionProcess: NetworkingIcmpv6ConnectivityExceptionProcess,
			ImpactStatement: NetworkingIcmpv6ConnectivityImpactStatement,
			Qe: false,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "networking-icmpv6-connectivity-multus",
			Category: checks.CategoryNetworking,
			CatalogID: "icmpv6-connectivity-multus",
			Fn:       CheckICMPv6ConnectivityMultus,
			Description: NetworkingIcmpv6ConnectivityMultusDescription,
			Remediation: NetworkingIcmpv6ConnectivityMultusRemediation,
			BestPracticeReference: NetworkingIcmpv6ConnectivityMultusBestPracticeRef,
			ExceptionProcess: NetworkingIcmpv6ConnectivityMultusExceptionProcess,
			ImpactStatement: NetworkingIcmpv6ConnectivityMultusImpactStatement,
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
			Name:     "networking-network-attachment-definition-sriov-mtu",
			Category: checks.CategoryNetworking,
			CatalogID: "network-attachment-definition-sriov-mtu",
			Fn:       CheckSRIOVNetworkAttachmentDefinitionMTU,
			Description: NetworkingNetworkAttachmentDefinitionSriovMtuDescription,
			Remediation: NetworkingNetworkAttachmentDefinitionSriovMtuRemediation,
			BestPracticeReference: NetworkingNetworkAttachmentDefinitionSriovMtuBestPracticeRef,
			ExceptionProcess: NetworkingNetworkAttachmentDefinitionSriovMtuExceptionProcess,
			ImpactStatement: NetworkingNetworkAttachmentDefinitionSriovMtuImpactStatement,
			Qe: false,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "networking-network-policy-deny-all",
			Category: checks.CategoryNetworking,
			CatalogID: "networking-network-policy-deny-all",
			Fn:       CheckNetworkPolicyDenyAll,
			Description: NetworkingNetworkPolicyDenyAllDescription,
			Remediation: NetworkingNetworkPolicyDenyAllRemediation,
			BestPracticeReference: NetworkingNetworkPolicyDenyAllBestPracticeRef,
			ExceptionProcess: NetworkingNetworkPolicyDenyAllExceptionProcess,
			ImpactStatement: NetworkingNetworkPolicyDenyAllImpactStatement,
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
			Name:     "networking-ocp-reserved-ports-usage",
			Category: checks.CategoryNetworking,
			CatalogID: "networking-ocp-reserved-ports-usage",
			Fn:       CheckOCPReservedPorts,
			Description: NetworkingOcpReservedPortsUsageDescription,
			Remediation: NetworkingOcpReservedPortsUsageRemediation,
			BestPracticeReference: NetworkingOcpReservedPortsUsageBestPracticeRef,
			ExceptionProcess: NetworkingOcpReservedPortsUsageExceptionProcess,
			ImpactStatement: NetworkingOcpReservedPortsUsageImpactStatement,
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
			Name:     "networking-reserved-partner-ports",
			Category: checks.CategoryNetworking,
			CatalogID: "networking-reserved-partner-ports",
			Fn:       CheckReservedPartnerPorts,
			Description: NetworkingReservedPartnerPortsDescription,
			Remediation: NetworkingReservedPartnerPortsRemediation,
			BestPracticeReference: NetworkingReservedPartnerPortsBestPracticeRef,
			ExceptionProcess: NetworkingReservedPartnerPortsExceptionProcess,
			ImpactStatement: NetworkingReservedPartnerPortsImpactStatement,
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
			Name:     "networking-restart-on-reboot-sriov-pod",
			Category: checks.CategoryNetworking,
			CatalogID: "networking-restart-on-reboot-sriov-pod",
			Fn:       CheckSRIOVRestartLabel,
			Description: NetworkingRestartOnRebootSriovPodDescription,
			Remediation: NetworkingRestartOnRebootSriovPodRemediation,
			BestPracticeReference: NetworkingRestartOnRebootSriovPodBestPracticeRef,
			ExceptionProcess: NetworkingRestartOnRebootSriovPodExceptionProcess,
			ImpactStatement: NetworkingRestartOnRebootSriovPodImpactStatement,
			Qe: false,
			Tags: []string{checks.TagFarEdge},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})

		checks.Register(checks.CheckInfo{
			Name:     "networking-undeclared-container-ports-usage",
			Category: checks.CategoryNetworking,
			CatalogID: "networking-undeclared-container-ports-usage",
			Fn:       CheckUndeclaredContainerPorts,
			Description: NetworkingUndeclaredContainerPortsUsageDescription,
			Remediation: NetworkingUndeclaredContainerPortsUsageRemediation,
			BestPracticeReference: NetworkingUndeclaredContainerPortsUsageBestPracticeRef,
			ExceptionProcess: NetworkingUndeclaredContainerPortsUsageExceptionProcess,
			ImpactStatement: NetworkingUndeclaredContainerPortsUsageImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Mandatory,
			},
		})
	})
}
