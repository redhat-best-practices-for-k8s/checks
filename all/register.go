// Package all provides a convenience function to register every check category.
package all

import (
	"github.com/redhat-best-practices-for-k8s/checks/accesscontrol"
	"github.com/redhat-best-practices-for-k8s/checks/certification"
	"github.com/redhat-best-practices-for-k8s/checks/lifecycle"
	"github.com/redhat-best-practices-for-k8s/checks/manageability"
	"github.com/redhat-best-practices-for-k8s/checks/networking"
	"github.com/redhat-best-practices-for-k8s/checks/observability"
	"github.com/redhat-best-practices-for-k8s/checks/operator"
	"github.com/redhat-best-practices-for-k8s/checks/performance"
	"github.com/redhat-best-practices-for-k8s/checks/platform"
)

// Register registers all check categories. Each category's Register()
// is idempotent, so calling this multiple times is safe.
func Register() {
	accesscontrol.Register()
	certification.Register()
	lifecycle.Register()
	manageability.Register()
	networking.Register()
	observability.Register()
	operator.Register()
	performance.Register()
	platform.Register()
}
