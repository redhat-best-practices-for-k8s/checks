package networking

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestResolveTLSProfile_Nil(t *testing.T) {
	policy := ResolveTLSProfile(nil)
	if policy.ProfileType != "Intermediate" {
		t.Errorf("expected Intermediate, got %s", policy.ProfileType)
	}
	if policy.MinTLSVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got 0x%04x", policy.MinTLSVersion)
	}
	if len(policy.AllowedCipherIDs) == 0 {
		t.Error("expected non-empty allowed cipher list for Intermediate")
	}
}

func TestResolveTLSProfile_Old(t *testing.T) {
	policy := ResolveTLSProfile(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType})
	if policy.ProfileType != "Old" {
		t.Errorf("expected Old, got %s", policy.ProfileType)
	}
	if policy.MinTLSVersion != tls.VersionTLS10 {
		t.Errorf("expected TLS 1.0, got 0x%04x", policy.MinTLSVersion)
	}
	intermediate := ResolveTLSProfile(nil)
	if len(policy.AllowedCipherIDs) <= len(intermediate.AllowedCipherIDs) {
		t.Errorf("expected Old to have more ciphers than Intermediate (%d vs %d)",
			len(policy.AllowedCipherIDs), len(intermediate.AllowedCipherIDs))
	}
}

func TestResolveTLSProfile_Modern(t *testing.T) {
	policy := ResolveTLSProfile(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType})
	if policy.ProfileType != "Modern" {
		t.Errorf("expected Modern, got %s", policy.ProfileType)
	}
	if policy.MinTLSVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got 0x%04x", policy.MinTLSVersion)
	}
	if len(policy.AllowedCipherIDs) != 0 {
		t.Errorf("expected no TLS 1.2 ciphers for Modern, got %d", len(policy.AllowedCipherIDs))
	}
}

func TestResolveTLSProfile_Custom(t *testing.T) {
	policy := ResolveTLSProfile(&configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileCustomType,
		Custom: &configv1.CustomTLSProfile{
			TLSProfileSpec: configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS12,
				Ciphers: []string{
					"ECDHE-ECDSA-AES128-GCM-SHA256",
					"ECDHE-RSA-AES128-GCM-SHA256",
				},
			},
		},
	})
	if policy.ProfileType != "Custom" {
		t.Errorf("expected Custom, got %s", policy.ProfileType)
	}
	if policy.MinTLSVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got 0x%04x", policy.MinTLSVersion)
	}
	if len(policy.AllowedCipherIDs) != 2 {
		t.Errorf("expected 2 allowed cipher IDs, got %d", len(policy.AllowedCipherIDs))
	}
}

func TestResolveTLSProfile_CustomNilSpec(t *testing.T) {
	policy := ResolveTLSProfile(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileCustomType})
	if policy.ProfileType != "Intermediate" {
		t.Errorf("expected Intermediate fallback, got %s", policy.ProfileType)
	}
}

func TestResolveTLSProfile_UnknownType(t *testing.T) {
	policy := ResolveTLSProfile(&configv1.TLSSecurityProfile{Type: "NotARealProfile"})
	if policy.ProfileType != "Intermediate" {
		t.Errorf("expected Intermediate fallback, got %s", policy.ProfileType)
	}
}

func TestDefaultTLSPolicy(t *testing.T) {
	policy := DefaultTLSPolicy()
	if policy.ProfileType != "Intermediate" {
		t.Errorf("expected Intermediate, got %s", policy.ProfileType)
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		ver  uint16
		want string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x9999, "unknown (0x9999)"},
	}
	for _, tt := range tests {
		if got := TLSVersionString(tt.ver); got != tt.want {
			t.Errorf("TLSVersionString(0x%04x) = %q, want %q", tt.ver, got, tt.want)
		}
	}
}

func TestVersionBelow(t *testing.T) {
	if versionBelow(tls.VersionTLS13) != tls.VersionTLS12 {
		t.Error("TLS 1.3 should be below TLS 1.2")
	}
	if versionBelow(tls.VersionTLS12) != tls.VersionTLS11 {
		t.Error("TLS 1.2 should be below TLS 1.1")
	}
	if versionBelow(tls.VersionTLS11) != tls.VersionTLS10 {
		t.Error("TLS 1.1 should be below TLS 1.0")
	}
	if versionBelow(tls.VersionTLS10) != 0 {
		t.Error("TLS 1.0 should have no version below")
	}
}

func TestVersionsAbove(t *testing.T) {
	above12 := versionsAbove(tls.VersionTLS12)
	if len(above12) != 1 || above12[0] != tls.VersionTLS13 {
		t.Errorf("versionsAbove(TLS1.2) = %v, want [TLS1.3]", above12)
	}
	if len(versionsAbove(tls.VersionTLS13)) != 0 {
		t.Error("nothing should be above TLS 1.3")
	}
}

func TestOcpVersionToGoVersion(t *testing.T) {
	if ocpVersionToGoVersion(configv1.VersionTLS10) != tls.VersionTLS10 {
		t.Error("TLS10 mapping failed")
	}
	if ocpVersionToGoVersion(configv1.VersionTLS13) != tls.VersionTLS13 {
		t.Error("TLS13 mapping failed")
	}
	if ocpVersionToGoVersion("TLSv99") != tls.VersionTLS12 {
		t.Error("unknown version should default to TLS 1.2")
	}
}

func TestComputeDisallowedOpenSSLCiphers_OldProfileAllowsAll(t *testing.T) {
	oldPolicy := ResolveTLSProfile(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType})
	if disallowed := computeDisallowedOpenSSLCiphers(oldPolicy); len(disallowed) != 0 {
		t.Errorf("Old profile should allow all known ciphers, got %v", disallowed)
	}
}
