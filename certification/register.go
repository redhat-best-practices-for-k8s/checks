package certification

import (
	"sync"

	"github.com/redhat-best-practices-for-k8s/checks"
)

var once sync.Once

func Register() {
	once.Do(func() {
		checks.Register(checks.CheckInfo{
			Name: "affiliated-certification-helm-version", Category: "affiliated-certification",
			Description: "Verifies Helm charts are deployed with Helm v3 (not v2 Tiller)",
			Remediation: "Remove Tiller and migrate to Helm v3",
			CatalogID:   "helm-version",
			Fn:          CheckHelmVersion,
		})
		checks.Register(checks.CheckInfo{
			Name: "affiliated-certification-container-is-certified-digest", Category: "affiliated-certification",
			Description: "Verifies container images are Red Hat certified by digest",
			Remediation: "Use container images that are certified in the Red Hat catalog",
			CatalogID:   "container-is-certified-digest",
			Fn:          CheckContainerCertified,
		})
		checks.Register(checks.CheckInfo{
			Name: "affiliated-certification-operator-is-certified", Category: "affiliated-certification",
			Description: "Verifies operators are Red Hat certified for the current OpenShift version",
			Remediation: "Use operators certified in the Red Hat catalog for your OpenShift version",
			CatalogID:   "operator-is-certified",
			Fn:          CheckOperatorCertified,
		})
		checks.Register(checks.CheckInfo{
			Name: "affiliated-certification-helmchart-is-certified", Category: "affiliated-certification",
			Description: "Verifies Helm charts are Red Hat certified",
			Remediation: "Use Helm charts that are certified in the Red Hat catalog",
			CatalogID:   "helmchart-is-certified",
			Fn:          CheckHelmChartCertified,
		})
	})
}
