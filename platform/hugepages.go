package platform

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

// CheckHugepages verifies hugepage configuration on nodes (probe-based).
func CheckHugepages(resources *checks.DiscoveredResources) checks.CheckResult {
	return ExecuteProbeCheck(resources, checkHugepagesNode, "%d node(s) have misconfigured hugepages")
}

func checkHugepagesNode(ctx context.Context, nodeName string, probePod *corev1.Pod, executor checks.ProbeExecutor) NodeCheckResult {
	stdout, _, err := executor.ExecCommand(ctx, probePod, "cat /host/proc/cmdline")
	if err != nil {
		return NodeCheckResult{Failed: true, FailureMessage: err.Error()}
	}

	// Only check hugepages if configured in boot params
	if !strings.Contains(stdout, "hugepagesz") && !strings.Contains(stdout, "hugepages=") {
		return NodeCheckResult{}
	}

	// Parse boot params to find configured hugepage sizes
	configuredSizes := parseHugepageSizes(stdout)
	if len(configuredSizes) == 0 {
		// Boot params mention hugepages but we couldn't parse sizes - pass the check
		return NodeCheckResult{}
	}

	// Read all hugepage allocations in a single exec command
	cmd := "cd /host/sys/kernel/mm/hugepages 2>/dev/null && for dir in hugepages-*kB; do [ -f \"$dir/nr_hugepages\" ] && echo \"$dir:$(cat $dir/nr_hugepages)\"; done"
	output, _, execErr := executor.ExecCommand(ctx, probePod, cmd)
	if execErr != nil {
		return NodeCheckResult{Failed: true, FailureMessage: execErr.Error()}
	}

	// Parse output into a map of size -> count
	allocations := make(map[int]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		// Format: "hugepages-2048kB:1024"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		// Extract size from "hugepages-2048kB"
		dirName := parts[0]
		if !strings.HasPrefix(dirName, "hugepages-") || !strings.HasSuffix(dirName, "kB") {
			continue
		}
		sizeStr := strings.TrimPrefix(dirName, "hugepages-")
		sizeStr = strings.TrimSuffix(sizeStr, "kB")
		if sizeKB, err := strconv.Atoi(sizeStr); err == nil {
			allocations[sizeKB] = strings.TrimSpace(parts[1])
		}
	}

	// Check each configured size
	var violations []checks.ResourceDetail
	for _, sizeKB := range configuredSizes {
		count, found := allocations[sizeKB]
		if !found {
			// Size not found in sysfs, skip
			continue
		}
		if count == "0" {
			violations = append(violations, checks.ResourceDetail{
				Kind:      "Node",
				Name:      nodeName,
				Namespace: "",
				Compliant: false,
				Message:   fmt.Sprintf("Hugepages size %dkB configured in boot params but nr_hugepages is 0", sizeKB),
			})
		}
	}

	if len(violations) > 0 {
		return NodeCheckResult{Violations: violations}
	}

	return NodeCheckResult{}
}

// parseHugepageSizes extracts hugepage sizes from kernel boot parameters.
// It looks for patterns like "hugepagesz=2M" or "default_hugepagesz=1G" and
// returns the sizes in kilobytes.
func parseHugepageSizes(cmdline string) []int {
	var sizes []int
	seenSizes := make(map[int]bool)

	for _, param := range strings.Fields(cmdline) {
		var sizeStr string
		var found bool

		if sizeStr, found = strings.CutPrefix(param, "hugepagesz="); !found {
			sizeStr, found = strings.CutPrefix(param, "default_hugepagesz=")
		}
		if !found {
			continue
		}

		if sizeKB, err := hugepageSizeToKB(sizeStr); err == nil && !seenSizes[sizeKB] {
			sizes = append(sizes, sizeKB)
			seenSizes[sizeKB] = true
		}
	}

	return sizes
}

// hugepageSizeToKB converts a hugepage size string to kilobytes.
// Supports formats like "2M", "1G", "2048", "2048kB".
// Returns size in kilobytes.
func hugepageSizeToKB(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	// Remove any trailing 'B' or 'b' (e.g., "2048kB" → "2048k")
	s = strings.TrimRight(s, "Bb")
	if s == "" {
		return 0, fmt.Errorf("invalid size string")
	}

	lastChar := s[len(s)-1]
	if unicode.IsDigit(rune(lastChar)) {
		// No unit specified, assume KB
		size, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("failed to parse size number: %w", err)
		}
		return size, nil
	}

	// Parse number and unit separately
	size, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, fmt.Errorf("failed to parse size number: %w", err)
	}

	switch strings.ToUpper(string(lastChar)) {
	case "K":
		return size, nil
	case "M":
		return size * 1024, nil
	case "G":
		return size * 1024 * 1024, nil
	case "T":
		return size * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("unknown size unit: %s", string(lastChar))
	}
}
