package networking

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func modernPolicy() TLSPolicy {
	return ResolveTLSProfile(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType})
}

func intermediatePolicy() TLSPolicy {
	return ResolveTLSProfile(nil)
}

func TestProbeServicePortViaExec_TLS13Enforced_ModernProfile(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "-tls1_3", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n---"},
		mockPattern{key: "-tls1_2", stdout: "CONNECTED(00000003)\n---\nssl handshake failure\n---"},
	)
	result := ProbeServicePortViaExec(context.Background(), mock, probePod(), "10.0.0.1", 443, modernPolicy())
	if !result.Compliant {
		t.Errorf("expected compliant, got: %s", result.Reason)
	}
	if result.NegotiatedVer != "TLS 1.3" {
		t.Errorf("expected TLS 1.3, got %s", result.NegotiatedVer)
	}
}

func TestProbeServicePortViaExec_AcceptsTLS12_ModernProfile(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "-tls1_3", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n---"},
		mockPattern{key: "-tls1_2", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.2\nCipher    : ECDHE-RSA-AES128-GCM-SHA256\n---"},
	)
	result := ProbeServicePortViaExec(context.Background(), mock, probePod(), "10.0.0.1", 443, modernPolicy())
	if result.Compliant {
		t.Error("expected non-compliant with Modern profile when TLS 1.2 is accepted")
	}
	if result.NegotiatedVer != "TLS 1.2" {
		t.Errorf("expected TLS 1.2, got %s", result.NegotiatedVer)
	}
}

func TestProbeServicePortViaExec_AcceptsTLS12_IntermediateProfile(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "-cipher", stdout: "CONNECTED(00000003)\n---\nssl handshake failure\n---"},
		mockPattern{key: "-tls1_3", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n---"},
		mockPattern{key: "-tls1_2", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.2\nCipher    : ECDHE-RSA-AES128-GCM-SHA256\n---"},
		mockPattern{key: "-tls1_1", stdout: "CONNECTED(00000003)\n---\nssl handshake failure\n---"},
	)
	result := ProbeServicePortViaExec(context.Background(), mock, probePod(), "10.0.0.1", 443, intermediatePolicy())
	if !result.Compliant {
		t.Errorf("expected compliant with Intermediate profile, got: %s", result.Reason)
	}
}

func TestProbeServicePortViaExec_ConnectionRefused(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "connect:errno=111\nConnection refused"},
	)
	result := ProbeServicePortViaExec(context.Background(), mock, probePod(), "10.0.0.1", 443, intermediatePolicy())
	if !result.Compliant {
		t.Errorf("unreachable should be compliant, got: %s", result.Reason)
	}
	if result.Reachable {
		t.Error("expected unreachable")
	}
}

func TestProbeServicePortViaExec_NonTLS(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "CONNECTED(00000003)\npacket length too long\nCipher is (NONE)"},
	)
	result := ProbeServicePortViaExec(context.Background(), mock, probePod(), "10.0.0.1", 80, intermediatePolicy())
	if !result.Compliant {
		t.Errorf("non-TLS should be informational compliant, got: %s", result.Reason)
	}
	if result.IsTLS {
		t.Error("expected IsTLS=false")
	}
	if !result.Reachable {
		t.Error("expected reachable")
	}
}

func TestProbeServicePortViaExec_ExecErrorNoOutput(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "", err: fmt.Errorf("command not found")},
	)
	result := ProbeServicePortViaExec(context.Background(), mock, probePod(), "10.0.0.1", 443, intermediatePolicy())
	if !result.Compliant {
		t.Errorf("exec failure should be treated as unreachable/compliant, got: %s", result.Reason)
	}
	if result.Reachable {
		t.Error("expected unreachable")
	}
}

func TestIsPortTLS_TLSServer(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n---"},
	)
	isTLS, reachable, reason := IsPortTLS(context.Background(), mock, probePod(), "10.0.0.1", 443)
	if !isTLS || !reachable {
		t.Errorf("expected TLS+reachable, isTLS=%v reachable=%v reason=%s", isTLS, reachable, reason)
	}
	if !strings.Contains(reason, "TLS negotiated") {
		t.Errorf("unexpected reason: %s", reason)
	}
}

func TestIsPortTLS_PlaintextService(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.2\n---"},
	)
	isTLS, reachable, reason := IsPortTLS(context.Background(), mock, probePod(), "10.0.0.1", 80)
	if isTLS {
		t.Errorf("expected plaintext, reason: %s", reason)
	}
	if !reachable {
		t.Error("expected reachable")
	}
	if !strings.Contains(reason, "plaintext") {
		t.Errorf("unexpected reason: %s", reason)
	}
}

func TestIsPortTLS_ConnectionRefused(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "connect:errno=111\nConnection refused"},
	)
	isTLS, reachable, reason := IsPortTLS(context.Background(), mock, probePod(), "10.0.0.1", 443)
	if isTLS || reachable {
		t.Errorf("expected unreachable, isTLS=%v reachable=%v reason=%s", isTLS, reachable, reason)
	}
}

func TestIsPortTLS_TLSHandshakeAlert(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "SSL routines:ssl3_read_bytes:sslv3 alert handshake failure", err: fmt.Errorf("exit status 1")},
	)
	isTLS, reachable, reason := IsPortTLS(context.Background(), mock, probePod(), "10.0.0.1", 443)
	if !isTLS || !reachable {
		t.Errorf("handshake alert is a TLS server, isTLS=%v reachable=%v reason=%s", isTLS, reachable, reason)
	}
	if strings.Contains(reason, "exec probe failed") {
		t.Errorf("should not be classified as exec failure: %s", reason)
	}
}

func TestIsPortTLS_ExecFailed(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "", err: fmt.Errorf("command not found")},
	)
	isTLS, reachable, reason := IsPortTLS(context.Background(), mock, probePod(), "10.0.0.1", 443)
	if isTLS || reachable {
		t.Errorf("expected exec failure, isTLS=%v reachable=%v reason=%s", isTLS, reachable, reason)
	}
	if !strings.Contains(reason, "exec probe failed") {
		t.Errorf("expected exec probe failed in reason, got %s", reason)
	}
}

func TestIsPortTLS_IPv6Address(t *testing.T) {
	mock := newContainsMock(
		mockPattern{key: "s_client", stdout: "CONNECTED(00000003)\n---\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\n---"},
	)
	isTLS, reachable, reason := IsPortTLS(context.Background(), mock, probePod(), "2001:db8::1", 443)
	if !isTLS || !reachable {
		t.Errorf("expected TLS over IPv6, isTLS=%v reachable=%v reason=%s", isTLS, reachable, reason)
	}
	if len(mock.commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.commands))
	}
	if !strings.Contains(mock.commands[0], "[2001:db8::1]:443") {
		t.Errorf("expected bracketed IPv6 connect string, got %s", mock.commands[0])
	}
}

func TestExtractOpenSSLCipher(t *testing.T) {
	tests := []struct {
		name, stdout, expected string
	}{
		{"with spaces", "Cipher    : ECDHE-RSA-AES128-GCM-SHA256\nProtocol  : TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"},
		{"without spaces", "Cipher: TLS_AES_256_GCM_SHA384\nProtocol: TLSv1.3", "TLS_AES_256_GCM_SHA384"},
		{"cipher 0000", "Cipher    : 0000\nProtocol  : TLSv1.2", "0000"},
		{"no cipher line", "Protocol  : TLSv1.2\nSome other output", "unknown"},
		{"empty output", "", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractOpenSSLCipher(tc.stdout); got != tc.expected {
				t.Errorf("got %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestHasOpensslOutput(t *testing.T) {
	if !hasOpensslOutput("CONNECTED(00000003)") {
		t.Error("CONNECTED should be recognized")
	}
	if !hasOpensslOutput("SSL routines") {
		t.Error("SSL should be recognized")
	}
	if hasOpensslOutput("plain http") {
		t.Error("plain text should not be recognized as openssl output")
	}
}

func TestOpensslHandshakeRejected(t *testing.T) {
	if !opensslHandshakeRejected("Cipher is (NONE)") {
		t.Error("cipher none should be rejected")
	}
	if opensslHandshakeRejected("Cipher    : TLS_AES_256_GCM_SHA384") {
		t.Error("successful cipher should not be rejected")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 200) != "short" {
		t.Error("short string should be unchanged")
	}
	if truncate("abcdef", 3) != "abc..." {
		t.Error("truncated string should append ...")
	}
}

func TestOpensslVersionFlagAndName(t *testing.T) {
	if opensslVersionFlag(tls.VersionTLS12) != "-tls1_2" {
		t.Error("flag mismatch")
	}
	if opensslVersionName(tls.VersionTLS12) != "TLSv1.2" {
		t.Error("name mismatch")
	}
	if opensslVersionFlag(0x1234) != "-tls1_2" {
		t.Error("unknown version should default to -tls1_2")
	}
}

func TestProbeExecCipherCompliance_TLS13SkipsCipherCheck(t *testing.T) {
	result := probeExecCipherCompliance(context.Background(), newContainsMock(), probePod(), "10.0.0.1:443", modernPolicy())
	if result != nil {
		t.Error("TLS 1.3 policy should skip cipher check")
	}
}

func TestClassifyExecNoMinVersion(t *testing.T) {
	policy := intermediatePolicy()
	r := classifyExecNoMinVersion("connect:errno=111 Connection refused", policy)
	if r.Reachable {
		t.Error("connection refused should be unreachable")
	}
	r = classifyExecNoMinVersion("alert protocol version", policy)
	if r.Compliant || !r.IsTLS {
		t.Errorf("TLS alert should be non-compliant TLS, got compliant=%v isTLS=%v", r.Compliant, r.IsTLS)
	}
	r = classifyExecNoMinVersion("CONNECTED Cipher is (NONE)", policy)
	if !r.Compliant || r.IsTLS {
		t.Errorf("non-TLS should be informational, got compliant=%v isTLS=%v", r.Compliant, r.IsTLS)
	}
}
