package networking

import (
	"crypto/tls"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
)

const (
	// OCPTLSProfileEnforcementVersion is the minimum OCP version at which the
	// APIServer CR's TLS security profile is reliably enforced.
	OCPTLSProfileEnforcementVersion = "4.22"

	tlsVersionNameTLS10 = "TLS 1.0"
	tlsVersionNameTLS11 = "TLS 1.1"
	tlsVersionNameTLS12 = "TLS 1.2"
	tlsVersionNameTLS13 = "TLS 1.3"

	cipherECDHERSAAES128GCMSHA256 = "ECDHE-RSA-AES128-GCM-SHA256"
)

// TLSPolicy holds the resolved effective TLS policy for the cluster.
type TLSPolicy struct {
	ProfileType        string
	MinTLSVersion      uint16   // Go crypto/tls constant (e.g. tls.VersionTLS12)
	AllowedCipherIDs   []uint16 // Go cipher suite IDs allowed for TLS 1.2
	AllowedCipherNames []string // OpenSSL cipher names allowed for TLS 1.2
}

// opensslToGoCipher maps OpenSSL cipher suite names to Go crypto/tls cipher suite IDs.
//
// The OpenSSL names come from the OpenShift TLS security profiles defined in:
//
//	https://github.com/openshift/api/blob/master/config/v1/types_tlssecurityprofile.go
//
// DHE ciphers (e.g. DHE-RSA-AES128-GCM-SHA256) have no Go equivalent and are omitted.
var opensslToGoCipher = map[string]uint16{
	"ECDHE-ECDSA-AES128-GCM-SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	cipherECDHERSAAES128GCMSHA256:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES256-GCM-SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES256-GCM-SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-CHACHA20-POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-RSA-CHACHA20-POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"AES128-GCM-SHA256":             tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"AES256-GCM-SHA384":             tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"AES128-SHA256":                 tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"AES128-SHA":                    tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"AES256-SHA":                    tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE-ECDSA-AES128-SHA256":     tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-RSA-AES128-SHA256":       tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-ECDSA-AES128-SHA":        tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"ECDHE-RSA-AES128-SHA":          tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-ECDSA-AES256-SHA384":     tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // closest Go mapping
	"ECDHE-RSA-AES256-SHA384":       tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,   // closest Go mapping
	"ECDHE-ECDSA-AES256-SHA":        tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE-RSA-AES256-SHA":          tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"DES-CBC3-SHA":                  tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var tls13CipherNames = map[string]bool{
	"TLS_AES_128_GCM_SHA256":       true,
	"TLS_AES_256_GCM_SHA384":       true,
	"TLS_CHACHA20_POLY1305_SHA256": true,
}

// DefaultTLSPolicy returns the Intermediate profile (OpenShift default).
func DefaultTLSPolicy() TLSPolicy {
	return ResolveTLSProfile(nil)
}

// ResolveTLSProfile converts an OpenShift TLSSecurityProfile into a TLSPolicy.
// A nil profile resolves to the Intermediate profile (the OpenShift default).
func ResolveTLSProfile(profile *configv1.TLSSecurityProfile) TLSPolicy {
	if profile == nil {
		return resolveTLSProfileSpec(string(configv1.TLSProfileIntermediateType),
			configv1.TLSProfiles[configv1.TLSProfileIntermediateType])
	}

	switch profile.Type {
	case configv1.TLSProfileOldType:
		return resolveTLSProfileSpec(string(configv1.TLSProfileOldType),
			configv1.TLSProfiles[configv1.TLSProfileOldType])
	case configv1.TLSProfileModernType:
		return resolveTLSProfileSpec(string(configv1.TLSProfileModernType),
			configv1.TLSProfiles[configv1.TLSProfileModernType])
	case configv1.TLSProfileCustomType:
		if profile.Custom != nil {
			spec := &profile.Custom.TLSProfileSpec
			return resolveTLSProfileSpec(string(configv1.TLSProfileCustomType), spec)
		}
		return resolveTLSProfileSpec(string(configv1.TLSProfileIntermediateType),
			configv1.TLSProfiles[configv1.TLSProfileIntermediateType])
	default:
		return resolveTLSProfileSpec(string(configv1.TLSProfileIntermediateType),
			configv1.TLSProfiles[configv1.TLSProfileIntermediateType])
	}
}

func ocpVersionToGoVersion(v configv1.TLSProtocolVersion) uint16 {
	switch v {
	case configv1.VersionTLS10:
		return tls.VersionTLS10
	case configv1.VersionTLS11:
		return tls.VersionTLS11
	case configv1.VersionTLS12:
		return tls.VersionTLS12
	case configv1.VersionTLS13:
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

func resolveTLSProfileSpec(profileType string, spec *configv1.TLSProfileSpec) TLSPolicy {
	policy := TLSPolicy{
		ProfileType:   profileType,
		MinTLSVersion: ocpVersionToGoVersion(spec.MinTLSVersion),
	}

	for _, cipherName := range spec.Ciphers {
		if tls13CipherNames[cipherName] {
			continue
		}
		policy.AllowedCipherNames = append(policy.AllowedCipherNames, cipherName)
		if id, ok := opensslToGoCipher[cipherName]; ok {
			policy.AllowedCipherIDs = append(policy.AllowedCipherIDs, id)
		}
	}

	return policy
}

func versionBelow(ver uint16) uint16 {
	switch ver {
	case tls.VersionTLS13:
		return tls.VersionTLS12
	case tls.VersionTLS12:
		return tls.VersionTLS11
	case tls.VersionTLS11:
		return tls.VersionTLS10
	default:
		return 0
	}
}

func versionsAbove(minVer uint16) []uint16 {
	allVersions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	var above []uint16
	for _, v := range allVersions {
		if v > minVer {
			above = append(above, v)
		}
	}
	return above
}

// TLSVersionString converts a Go TLS version constant to a human-readable string.
func TLSVersionString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return tlsVersionNameTLS10
	case tls.VersionTLS11:
		return tlsVersionNameTLS11
	case tls.VersionTLS12:
		return tlsVersionNameTLS12
	case tls.VersionTLS13:
		return tlsVersionNameTLS13
	default:
		return fmt.Sprintf("unknown (0x%04x)", ver)
	}
}
