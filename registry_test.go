package checks

import (
	"testing"
)

func TestRegisterAndAll(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = nil
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	Register(CheckInfo{Name: "check-a", Category: "cat-a", Fn: func(r *DiscoveredResources) CheckResult {
		return CheckResult{ComplianceStatus: "Compliant"}
	}})
	Register(CheckInfo{Name: "check-b", Category: "cat-b", Fn: func(r *DiscoveredResources) CheckResult {
		return CheckResult{ComplianceStatus: "NonCompliant"}
	}})

	all := All()
	if len(all) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(all))
	}
	if all[0].Name != "check-a" {
		t.Errorf("expected check-a, got %s", all[0].Name)
	}
}

func TestFiltered(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = nil
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	Register(CheckInfo{Name: "check-a", Fn: func(r *DiscoveredResources) CheckResult {
		return CheckResult{}
	}})
	Register(CheckInfo{Name: "check-b", Fn: func(r *DiscoveredResources) CheckResult {
		return CheckResult{}
	}})
	Register(CheckInfo{Name: "check-c", Fn: func(r *DiscoveredResources) CheckResult {
		return CheckResult{}
	}})

	// Empty filter returns all
	filtered := Filtered(nil)
	if len(filtered) != 3 {
		t.Fatalf("expected 3, got %d", len(filtered))
	}

	// Specific filter
	filtered = Filtered([]string{"check-a", "check-c"})
	if len(filtered) != 2 {
		t.Fatalf("expected 2, got %d", len(filtered))
	}
}

func TestByCategory(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = nil
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	Register(CheckInfo{Name: "check-a", Category: "cat-a", Fn: func(r *DiscoveredResources) CheckResult {
		return CheckResult{}
	}})
	Register(CheckInfo{Name: "check-b", Category: "cat-b", Fn: func(r *DiscoveredResources) CheckResult {
		return CheckResult{}
	}})
	Register(CheckInfo{Name: "check-c", Category: "cat-a", Fn: func(r *DiscoveredResources) CheckResult {
		return CheckResult{}
	}})

	catA := ByCategory("cat-a")
	if len(catA) != 2 {
		t.Fatalf("expected 2, got %d", len(catA))
	}

	catB := ByCategory("cat-b")
	if len(catB) != 1 {
		t.Fatalf("expected 1, got %d", len(catB))
	}

	catC := ByCategory("cat-c")
	if len(catC) != 0 {
		t.Fatalf("expected 0, got %d", len(catC))
	}
}
