package checks

// Tag constants for check classification.
const (
	TagCommon   = "common"
	TagExtended = "extended"
	TagTelco    = "telco"
	TagFarEdge  = "faredge"
)

// Category constants for CheckInfo.Category.
const (
	CategoryAccessControl          = "access-control"
	CategoryAffiliatedCertification = "affiliated-certification"
	CategoryLifecycle              = "lifecycle"
	CategoryManageability          = "manageability"
	CategoryNetworking             = "networking"
	CategoryObservability          = "observability"
	CategoryOperator               = "operator"
	CategoryPerformance            = "performance"
	CategoryPlatformAlteration     = "platform-alteration"
)

// Scenario constants for CategoryClassification keys.
const (
	FarEdge  = "FarEdge"
	Telco    = "Telco"
	NonTelco = "NonTelco"
	Extended = "Extended"
)

// Classification values for CategoryClassification.
const (
	Optional  = "Optional"
	Mandatory = "Mandatory"
)

// Sentinel strings for common metadata values.
const (
	NoExceptionProcess          = "There is no documented exception process for this."
	NoExceptionProcessExtended  = "No exception needed for optional/extended tests."
	NoExceptions                = "No exceptions"
	NoDocLink                   = "No Doc Link"
	NoDocLinkExtended           = "No Doc Link - Extended"
	NoDocLinkFarEdge            = "No Doc Link - Far Edge"
	NoDocLinkTelco              = "No Doc Link - Telco"
)
