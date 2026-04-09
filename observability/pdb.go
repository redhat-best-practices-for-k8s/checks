package observability

import (
	"fmt"
	"math"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/redhat-best-practices-for-k8s/checks"
)

const (
	percentageDivisor = 100
	zoneTopologyLabel = "topology.kubernetes.io/zone"
)

// CheckPodDisruptionBudget verifies PodDisruptionBudgets exist and are valid
// for all Deployments and StatefulSets. It mirrors the certsuite logic:
//  1. Iterates both Deployments AND StatefulSets
//  2. For each workload, finds matching PDBs using proper label selector matching
//  3. If no PDB matches, the workload is non-compliant
//  4. For matching PDBs, validates basic validity and zone-awareness
func CheckPodDisruptionBudget(resources *checks.DiscoveredResources) checks.CheckResult {
	result := checks.CheckResult{ComplianceStatus: checks.StatusCompliant}
	if len(resources.Deployments) == 0 && len(resources.StatefulSets) == 0 {
		result.Reason = "No deployments or statefulsets found"
		return result
	}

	numZones := countWorkerZones(resources)
	var nonCompliantCount int

	// Check Deployments
	for i := range resources.Deployments {
		deploy := &resources.Deployments[i]
		details := checkWorkloadPDB(
			"Deployment", deploy.Name, deploy.Namespace,
			deploy.Spec.Template.Labels, deploy.Spec.Replicas,
			resources.PodDisruptionBudgets, numZones,
		)
		for _, d := range details {
			if !d.Compliant {
				nonCompliantCount++
			}
			result.Details = append(result.Details, d)
		}
	}

	// Check StatefulSets
	for i := range resources.StatefulSets {
		sts := &resources.StatefulSets[i]
		details := checkWorkloadPDB(
			"StatefulSet", sts.Name, sts.Namespace,
			sts.Spec.Template.Labels, sts.Spec.Replicas,
			resources.PodDisruptionBudgets, numZones,
		)
		for _, d := range details {
			if !d.Compliant {
				nonCompliantCount++
			}
			result.Details = append(result.Details, d)
		}
	}

	if nonCompliantCount > 0 {
		result.ComplianceStatus = checks.StatusNonCompliant
		result.Reason = fmt.Sprintf("%d workload(s) have PodDisruptionBudget issues", nonCompliantCount)
	}
	return result
}

// checkWorkloadPDB finds matching PDBs for a workload and validates them.
// Returns one or more resource details for the workload.
func checkWorkloadPDB(
	kind, name, namespace string,
	templateLabels map[string]string,
	replicas *int32,
	pdbs []policyv1.PodDisruptionBudget,
	numZones int,
) []checks.ResourceDetail {
	workloadSelector := labels.Set(templateLabels)
	pdbFound := false

	var details []checks.ResourceDetail

	for i := range pdbs {
		pdb := &pdbs[i]
		if pdb.Namespace != namespace {
			continue
		}

		pdbSelector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}

		if !pdbSelector.Matches(workloadSelector) {
			continue
		}

		pdbFound = true

		// Basic PDB validity check
		ok, err := checkPDBIsValid(pdb, replicas)
		if !ok {
			details = append(details, checks.ResourceDetail{
				Kind: kind, Name: name, Namespace: namespace,
				Compliant: false,
				Message:   fmt.Sprintf("Invalid PodDisruptionBudget %q config: %v", pdb.Name, err),
			})
			continue
		}

		// Zone-awareness check
		zoneResult := checkPDBIsZoneAware(pdb, replicas, numZones)
		if !zoneResult.IsValid {
			details = append(details, checks.ResourceDetail{
				Kind: kind, Name: name, Namespace: namespace,
				Compliant: false,
				Message:   fmt.Sprintf("PodDisruptionBudget %q is not zone-aware: %v", pdb.Name, zoneResult.ZoneCheckError),
			})
			continue
		}

		details = append(details, checks.ResourceDetail{
			Kind: kind, Name: name, Namespace: namespace,
			Compliant: true,
			Message:   fmt.Sprintf("References valid and zone-aware PodDisruptionBudget %q", pdb.Name),
		})
	}

	if !pdbFound {
		details = append(details, checks.ResourceDetail{
			Kind: kind, Name: name, Namespace: namespace,
			Compliant: false,
			Message:   fmt.Sprintf("%s is missing a corresponding PodDisruptionBudget", kind),
		})
	}

	return details
}

// countWorkerZones counts the number of unique zones across all nodes.
func countWorkerZones(resources *checks.DiscoveredResources) int {
	zones := make(map[string]bool)
	for i := range resources.Nodes {
		if zone, ok := resources.Nodes[i].Labels[zoneTopologyLabel]; ok && zone != "" {
			zones[zone] = true
		}
	}
	return len(zones)
}

// replicaCountOrDefault dereferences replicas, defaulting to 1 if nil.
func replicaCountOrDefault(replicas *int32) int32 {
	if replicas != nil {
		return *replicas
	}
	return 1
}

// percentageToFloat converts a percentage string to a float.
func percentageToFloat(percentage string) (float64, error) {
	var percentageFloat float64
	_, err := fmt.Sscanf(percentage, "%f%%", &percentageFloat)
	if err != nil {
		return 0, err
	}
	return percentageFloat / percentageDivisor, nil
}

// intOrStringToValue converts a PDB value (integer or percentage) to an absolute integer.
func intOrStringToValue(intOrStr *intstr.IntOrString, replicas int32) (int, error) {
	switch intOrStr.Type {
	case intstr.Int:
		return intOrStr.IntValue(), nil
	case intstr.String:
		v, err := percentageToFloat(intOrStr.StrVal)
		if err != nil {
			return 0, fmt.Errorf("invalid value %q: %v", intOrStr.StrVal, err)
		}
		return int(math.RoundToEven(v * float64(replicas))), nil
	}
	return 0, fmt.Errorf("invalid type: neither int nor percentage")
}

// checkPDBIsValid validates basic PDB configuration against replica count.
func checkPDBIsValid(pdb *policyv1.PodDisruptionBudget, replicas *int32) (bool, error) {
	replicaCount := replicaCountOrDefault(replicas)

	if pdb.Spec.MinAvailable != nil {
		minAvailableValue, err := intOrStringToValue(pdb.Spec.MinAvailable, replicaCount)
		if err != nil {
			return false, err
		}

		if minAvailableValue == 0 {
			return false, fmt.Errorf("field .spec.minAvailable cannot be zero. Currently set to: %d. Replicas set to: %d", minAvailableValue, replicaCount)
		}

		if minAvailableValue > int(replicaCount) {
			return false, fmt.Errorf("minAvailable cannot be greater than replicas. Currently set to: %d. Replicas set to: %d", minAvailableValue, replicaCount)
		}
	}

	if pdb.Spec.MaxUnavailable != nil {
		maxUnavailableValue, err := intOrStringToValue(pdb.Spec.MaxUnavailable, replicaCount)
		if err != nil {
			return false, err
		}

		if maxUnavailableValue >= int(replicaCount) {
			return false, fmt.Errorf("field .spec.maxUnavailable cannot be greater than or equal to the number of pods in the replica. Currently set to: %d. Replicas set to: %d", maxUnavailableValue, replicaCount)
		}
	}

	return true, nil
}

// zoneAwareCheckResult contains the result of a zone-aware PDB validation.
type zoneAwareCheckResult struct {
	IsValid        bool
	ZoneCheckError error
}

// checkPDBIsZoneAware validates that a PDB can tolerate an entire zone going offline.
func checkPDBIsZoneAware(pdb *policyv1.PodDisruptionBudget, replicas *int32, numZones int) *zoneAwareCheckResult {
	result := &zoneAwareCheckResult{}

	replicaCount := replicaCountOrDefault(replicas)

	// Skip zone-aware check for single-zone clusters or SNO
	if numZones <= 1 {
		result.IsValid = true
		return result
	}

	maxReplicasPerZone := int(math.Ceil(float64(replicaCount) / float64(numZones)))

	var minAvailableValue int
	var maxUnavailableValue int

	if pdb.Spec.MinAvailable != nil {
		var err error
		minAvailableValue, err = intOrStringToValue(pdb.Spec.MinAvailable, replicaCount)
		if err != nil {
			result.ZoneCheckError = fmt.Errorf("failed to parse minAvailable: %v", err)
			return result
		}
	}

	if pdb.Spec.MaxUnavailable != nil {
		var err error
		maxUnavailableValue, err = intOrStringToValue(pdb.Spec.MaxUnavailable, replicaCount)
		if err != nil {
			result.ZoneCheckError = fmt.Errorf("failed to parse maxUnavailable: %v", err)
			return result
		}
	}

	// Check if PDB allows draining all pods in a single zone
	zoneAware := pdb.Spec.MaxUnavailable != nil && maxUnavailableValue >= maxReplicasPerZone
	if pdb.Spec.MinAvailable != nil {
		maxAllowedMinAvailable := int(replicaCount) - maxReplicasPerZone
		if minAvailableValue <= maxAllowedMinAvailable {
			zoneAware = true
		}
	}

	if !zoneAware {
		minAllowedMaxUnavailable := maxReplicasPerZone
		maxAllowedMinAvailable := int(replicaCount) - maxReplicasPerZone
		result.ZoneCheckError = fmt.Errorf(
			"PDB is not zone-aware: with %d replicas across %d zones, max %d pods could be in one zone. "+
				"Either set maxUnavailable >= %d or minAvailable <= %d to survive a zone failure",
			replicaCount, numZones, maxReplicasPerZone,
			minAllowedMaxUnavailable, maxAllowedMinAvailable)
		return result
	}

	result.IsValid = true
	return result
}
