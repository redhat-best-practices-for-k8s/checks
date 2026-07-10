# CLAUDE.md

## Project Overview

Shared best-practice check library for Kubernetes workloads. This Go module provides reusable compliance checks consumed by the [certsuite](https://github.com/redhat-best-practices-for-k8s/certsuite) CLI and the [bps-operator](https://github.com/sebrandon1/bps-operator).

Each check is a pure function with signature `func(resources *DiscoveredResources) CheckResult` that evaluates Kubernetes resources against best-practice criteria.

## Common Commands

```bash
make test          # Run all tests with coverage
make lint          # Run golangci-lint (govet, errcheck, staticcheck, unused, ineffassign)
make vet           # Run go vet
make fmt           # Run go fmt
make map-uts       # Map unit test coverage via script/map-uts.sh
```

## Architecture

### Core Package (`checks.go`, `registry.go`)

- `DiscoveredResources` -- struct holding all K8s objects (Pods, Services, Deployments, Nodes, CSVs, CRDs, etc.)
- `CheckFunc` -- `func(resources *DiscoveredResources) CheckResult`
- `CheckInfo` -- registered check descriptor (name, category, description, metadata, function)
- `CheckResult` -- outcome with `ComplianceStatus` (Compliant/NonCompliant/Skipped/Error), reason, and per-resource details
- Global registry with `Register()`, `All()`, `Filtered()`, `ByName()`, `ByCategory()`

### Check Categories (one package each)

| Package | Category Constant |
|---|---|
| `accesscontrol/` | `CategoryAccessControl` ("access-control") |
| `certification/` | `CategoryAffiliatedCertification` ("affiliated-certification") |
| `lifecycle/` | `CategoryLifecycle` ("lifecycle") |
| `manageability/` | `CategoryManageability` ("manageability") |
| `networking/` | `CategoryNetworking` ("networking") |
| `observability/` | `CategoryObservability` ("observability") |
| `operator/` | `CategoryOperator` ("operator") |
| `performance/` | `CategoryPerformance` ("performance") |
| `platform/` | `CategoryPlatformAlteration` ("platform-alteration") |

### Other Packages

- `all/` -- convenience `Register()` that registers all categories
- `testutil/` -- test helpers and mock implementations

### Key Files Per Category

Each category package follows the same structure:

- `register.go` -- `Register()` with `sync.Once`, calls `checks.Register()` for each check
- `metadata.go` -- description, remediation, best-practice reference, and impact statement constants
- Implementation files (e.g., `capabilities.go`, `probes.go`, `ports.go`)
- `*_test.go` -- unit tests

### Helpers

- `iteration_helpers.go` -- `ForEachPodContainer()` and `ForEachContainer()` for iterating pods/containers
- `probe_helpers.go` -- helpers for probe-based checks requiring `ProbeExecutor`
- `metadata.go` -- tag, category, and classification constants

## How to Add a New Check

1. Choose the appropriate category package (e.g., `lifecycle/`)
2. Create an implementation file with a function matching `CheckFunc` signature:
   ```go
   func CheckMyNewThing(resources *checks.DiscoveredResources) checks.CheckResult { ... }
   ```
3. Add metadata constants in `metadata.go`:
   ```go
   MyCheckDescription = `Description text`
   MyCheckRemediation = `Remediation text`
   // ... BestPracticeRef, ExceptionProcess, ImpactStatement
   ```
4. Register in `register.go` inside the `once.Do()` block:
   ```go
   checks.Register(checks.CheckInfo{
       Name:        "category-my-new-check",
       Category:    checks.CategoryLifecycle,
       CatalogID:   "category-my-new-check",
       Fn:          CheckMyNewThing,
       Description: MyCheckDescription,
       Remediation: MyCheckRemediation,
       // ... other metadata fields
       Tags: []string{checks.TagCommon},
       CategoryClassification: map[string]string{
           checks.FarEdge: checks.Mandatory,
           checks.Telco:   checks.Mandatory,
           checks.NonTelco: checks.Optional,
           checks.Extended: checks.Mandatory,
       },
   })
   ```
5. Write unit tests in the category's `*_test.go` file
6. Update `README.md` check catalog table with the new check
7. Run `make lint && make test` before committing

## Requirements

- Go 1.26.3+ (toolchain 1.26.4)
- golangci-lint for linting

## Code Style

- Linter config: `.golangci.yml` enables govet, errcheck, staticcheck, unused, ineffassign
- Always handle errors from `resp.Body.Close()` with blank identifier: `_ = resp.Body.Close()`
- Use `defer func() { _ = f.Close() }()` for deferred close calls
- Checks should return `StatusSkipped` when required resources are not available
- Use `ForEachPodContainer()` / `ForEachContainer()` helpers instead of manual pod/container loops
- Skip `istio-proxy` containers using `IsIgnoredContainer()`
- Compliance statuses: `StatusCompliant`, `StatusNonCompliant`, `StatusSkipped`, `StatusError`
