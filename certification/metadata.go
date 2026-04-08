package certification

import "github.com/redhat-best-practices-for-k8s/checks"

// Metadata constants migrated from certsuite identifiers.

// Descriptions
const (
	AffiliatedCertificationContainerIsCertifiedDigestDescription = `Tests whether container images that are autodiscovered have passed the Red Hat Container Certification Program by their digest(CCP).`

	AffiliatedCertificationHelmVersionDescription = `Test to check if the helm chart is v3`

	AffiliatedCertificationHelmchartIsCertifiedDescription = `Tests whether helm charts listed in the cluster passed the Red Hat Helm Certification Program.`

	AffiliatedCertificationOperatorIsCertifiedDescription = `Tests whether the workload Operators listed in the configuration file have passed the Red Hat Operator Certification Program (OCP).`

)

// Remediations
const (
	AffiliatedCertificationContainerIsCertifiedDigestRemediation = `Ensure that your container has passed the Red Hat Container Certification Program (CCP).`

	AffiliatedCertificationHelmVersionRemediation = `Check Helm Chart is v3 and not v2 which is not supported due to security risks associated with Tiller.`

	AffiliatedCertificationHelmchartIsCertifiedRemediation = `Ensure that the helm charts under test passed the Red Hat's helm Certification Program (e.g. listed in https://charts.openshift.io/index.yaml).`

	AffiliatedCertificationOperatorIsCertifiedRemediation = `Ensure that your Operator has passed Red Hat's Operator Certification Program (OCP).`

)

// Best practice references
const (
	AffiliatedCertificationContainerIsCertifiedDigestBestPracticeRef = `https://docs.redhat.com/en/documentation/red_hat_software_certification/2025/html/red_hat_software_certification_workflow_guide/index`

	AffiliatedCertificationHelmVersionBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-helm`

	AffiliatedCertificationHelmchartIsCertifiedBestPracticeRef = `https://docs.redhat.com/en/documentation/red_hat_software_certification/2025/html/red_hat_software_certification_workflow_guide/index`

	AffiliatedCertificationOperatorIsCertifiedBestPracticeRef = `https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-cnf-operator-requirements`

)

// Exception processes
const (
	AffiliatedCertificationContainerIsCertifiedDigestExceptionProcess = `There is no documented exception process for this. A partner can run the Red Hat Best Practices Test Suite before passing other certifications (Container/Operator/HelmChart) but the affiliated certification test cases in the Red Hat Best Practices Test Suite must be re-run once the other certifications have been granted.`

	AffiliatedCertificationHelmVersionExceptionProcess = checks.NoExceptionProcess

	AffiliatedCertificationHelmchartIsCertifiedExceptionProcess = `There is no documented exception process for this. A partner can run the Red Hat Best Practices Test Suite before passing other certifications (Container/Operator/HelmChart) but the affiliated certification test cases in the Red Hat Best Practices Test Suite must be re-run once the other certifications have been granted.`

	AffiliatedCertificationOperatorIsCertifiedExceptionProcess = `There is no documented exception process for this. A partner can run the Red Hat Best Practices Test Suite before passing other certifications (Container/Operator/HelmChart) but the affiliated certification test cases in the Red Hat Best Practices Test Suite must be re-run once the other certifications have been granted.`

)

// Impact statements
const (
	AffiliatedCertificationContainerIsCertifiedDigestImpactStatement = `Uncertified containers may contain security vulnerabilities, lack enterprise support, and fail to meet compliance requirements.`

	AffiliatedCertificationHelmVersionImpactStatement = `Helm v2 has known security vulnerabilities and lacks proper RBAC controls, creating significant security risks in production environments.`

	AffiliatedCertificationHelmchartIsCertifiedImpactStatement = `Uncertified helm charts may contain security vulnerabilities, configuration errors, and lack proper testing, leading to deployment failures.`

	AffiliatedCertificationOperatorIsCertifiedImpactStatement = `Uncertified operators may have security flaws, compatibility issues, and lack enterprise support, creating operational risks.`

)
