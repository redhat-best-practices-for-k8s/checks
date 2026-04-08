package manageability

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "manageability-container-port-name-format",
			Category: checks.CategoryManageability,
			CatalogID: "manageability-container-port-name-format",
			Fn:       CheckPortNameFormat,
			Description: ManageabilityContainerPortNameFormatDescription,
			Remediation: ManageabilityContainerPortNameFormatRemediation,
			BestPracticeReference: ManageabilityContainerPortNameFormatBestPracticeRef,
			ExceptionProcess: ManageabilityContainerPortNameFormatExceptionProcess,
			ImpactStatement: ManageabilityContainerPortNameFormatImpactStatement,
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
			Name:     "manageability-containers-image-tag",
			Category: checks.CategoryManageability,
			CatalogID: "manageability-containers-image-tag",
			Fn:       CheckImageTag,
			Description: ManageabilityContainersImageTagDescription,
			Remediation: ManageabilityContainersImageTagRemediation,
			BestPracticeReference: ManageabilityContainersImageTagBestPracticeRef,
			ExceptionProcess: ManageabilityContainersImageTagExceptionProcess,
			ImpactStatement: ManageabilityContainersImageTagImpactStatement,
			Qe: true,
			Tags: []string{checks.TagExtended},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Optional,
				checks.Telco: checks.Optional,
				checks.NonTelco: checks.Optional,
				checks.Extended: checks.Optional,
			},
		})
	})
}
