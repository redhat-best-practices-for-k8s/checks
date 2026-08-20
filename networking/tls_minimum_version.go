package networking

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

func firstProbePod(resources *checks.DiscoveredResources) *corev1.Pod {
	for _, probePod := range resources.ProbePods {
		if probePod != nil {
			return probePod
		}
	}
	return nil
}

// CheckTLSMinimumVersion verifies TLS-enabled services honor the cluster TLS security profile.
func CheckTLSMinimumVersion(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}

	if resources.ProbeExecutor == nil || firstProbePod(resources) == nil {
		result.ComplianceStatus = checks.StatusSkipped
		result.Reason = "Probe pods not available"
		return result
	}

	if len(resources.Services) == 0 {
		result.Reason = "No services found"
		return result
	}

	policy := ResolveTLSProfile(resources.TLSSecurityProfile)
	probePod := firstProbePod(resources)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var nonCompliant int
	for i := range resources.Services {
		svc := &resources.Services[i]
		if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
			continue
		}

		for _, port := range svc.Spec.Ports {
			if port.Protocol != corev1.ProtocolTCP {
				continue
			}

			probe := ProbeServicePortViaExec(ctx, resources.ProbeExecutor, probePod, svc.Spec.ClusterIP, port.Port, policy)
			if !probe.Reachable {
				probe.Compliant = true
			}

			detail := checks.ResourceDetail{
				Kind:      "Service",
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Compliant: probe.Compliant,
				Message:   fmt.Sprintf("port %d: %s", port.Port, probe.Reason),
			}
			if probe.NegotiatedVer != "" {
				detail.Message += " (negotiated " + probe.NegotiatedVer + ")"
			}
			result.Details = append(result.Details, detail)
			if !probe.Compliant {
				nonCompliant++
			}
		}
	}

	if nonCompliant > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d service port(s) do not honor the %s TLS profile (min %s)",
			nonCompliant, policy.ProfileType, TLSVersionString(policy.MinTLSVersion))
		return result
	}

	if len(result.Details) == 0 {
		result.Reason = "No TCP ClusterIP services to probe"
		return result
	}

	result.Reason = fmt.Sprintf("All probed service ports honor the %s TLS profile (min %s)",
		policy.ProfileType, TLSVersionString(policy.MinTLSVersion))
	return result
}
