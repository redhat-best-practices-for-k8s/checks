package certification

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name:     "affiliated-certification-container-is-certified-digest",
			Category: "affiliated-certification",
			CatalogID: "container-is-certified-digest",
			Fn:       CheckContainerCertified,
			Description: AffiliatedCertificationContainerIsCertifiedDigestDescription,
			Remediation: AffiliatedCertificationContainerIsCertifiedDigestRemediation,
			BestPracticeReference: AffiliatedCertificationContainerIsCertifiedDigestBestPracticeRef,
			ExceptionProcess: AffiliatedCertificationContainerIsCertifiedDigestExceptionProcess,
			ImpactStatement: AffiliatedCertificationContainerIsCertifiedDigestImpactStatement,
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
			Name:     "affiliated-certification-helm-version",
			Category: "affiliated-certification",
			CatalogID: "helm-version",
			Fn:       CheckHelmVersion,
			Description: AffiliatedCertificationHelmVersionDescription,
			Remediation: AffiliatedCertificationHelmVersionRemediation,
			BestPracticeReference: AffiliatedCertificationHelmVersionBestPracticeRef,
			ExceptionProcess: AffiliatedCertificationHelmVersionExceptionProcess,
			ImpactStatement: AffiliatedCertificationHelmVersionImpactStatement,
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
			Name:     "affiliated-certification-helmchart-is-certified",
			Category: "affiliated-certification",
			CatalogID: "helmchart-is-certified",
			Fn:       CheckHelmChartCertified,
			Description: AffiliatedCertificationHelmchartIsCertifiedDescription,
			Remediation: AffiliatedCertificationHelmchartIsCertifiedRemediation,
			BestPracticeReference: AffiliatedCertificationHelmchartIsCertifiedBestPracticeRef,
			ExceptionProcess: AffiliatedCertificationHelmchartIsCertifiedExceptionProcess,
			ImpactStatement: AffiliatedCertificationHelmchartIsCertifiedImpactStatement,
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
			Name:     "affiliated-certification-operator-is-certified",
			Category: "affiliated-certification",
			CatalogID: "operator-is-certified",
			Fn:       CheckOperatorCertified,
			Description: AffiliatedCertificationOperatorIsCertifiedDescription,
			Remediation: AffiliatedCertificationOperatorIsCertifiedRemediation,
			BestPracticeReference: AffiliatedCertificationOperatorIsCertifiedBestPracticeRef,
			ExceptionProcess: AffiliatedCertificationOperatorIsCertifiedExceptionProcess,
			ImpactStatement: AffiliatedCertificationOperatorIsCertifiedImpactStatement,
			Qe: true,
			Tags: []string{checks.TagCommon},
			CategoryClassification: map[string]string{
				checks.FarEdge: checks.Mandatory,
				checks.Telco: checks.Mandatory,
				checks.NonTelco: checks.Mandatory,
				checks.Extended: checks.Mandatory,
			},
		})
	})
}
