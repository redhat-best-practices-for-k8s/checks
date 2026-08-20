package networking

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/redhat-best-practices-for-k8s/checks"
)

const (
	opensslFlagTLS10 = "-tls1"
	opensslFlagTLS11 = "-tls1_1"
	opensslFlagTLS12 = "-tls1_2"
	opensslFlagTLS13 = "-tls1_3"

	opensslProtoNameTLS10 = "TLSv1"
	opensslProtoNameTLS11 = "TLSv1.1"
	opensslProtoNameTLS12 = "TLSv1.2"
	opensslProtoNameTLS13 = "TLSv1.3"

	truncateLen = 200

	opensslCipherNone       = "Cipher is (NONE)"
	opensslAlertProtoVer    = "alert protocol version"
	opensslAlertHandshake   = "alert handshake failure"
	opensslHandshakeFailure = "handshake failure"
	opensslNoCiphers        = "no ciphers available"
	opensslConnected        = "CONNECTED"
	opensslConnErrno        = "errno"

	reasonPortUnreachable = "port unreachable"
	reasonUnknown         = "unknown"
)

// TLSProbeResult holds the outcome of a TLS probe against a single service port.
type TLSProbeResult struct {
	Compliant     bool
	IsTLS         bool
	Reachable     bool
	NegotiatedVer string
	Reason        string
}

func execOpenSSL(ctx context.Context, executor checks.ProbeExecutor, probePod *corev1.Pod, cmd string) (string, error) {
	stdout, _, err := executor.ExecCommand(ctx, probePod, cmd)
	return stdout, err
}

// ProbeServicePortViaExec runs openssl s_client inside a probe pod to test
// TLS compliance against the given policy.
func ProbeServicePortViaExec(ctx context.Context, executor checks.ProbeExecutor, probePod *corev1.Pod, address string, port int32, policy TLSPolicy) TLSProbeResult {
	endpoint := net.JoinHostPort(address, strconv.Itoa(int(port)))

	if result := probeExecMinVersion(ctx, executor, probePod, endpoint, policy); result != nil {
		return *result
	}

	belowVer := versionBelow(policy.MinTLSVersion)
	if belowVer > 0 {
		if result := probeExecVersion(ctx, executor, probePod, endpoint, belowVer, false, policy); !result.Compliant {
			return result
		}
	}

	for _, aboveVer := range versionsAbove(policy.MinTLSVersion) {
		if result := probeExecVersion(ctx, executor, probePod, endpoint, aboveVer, true, policy); !result.Compliant {
			return result
		}
	}

	if result := probeExecCipherCompliance(ctx, executor, probePod, endpoint, policy); result != nil {
		return *result
	}

	return TLSProbeResult{
		Compliant:     true,
		IsTLS:         true,
		Reachable:     true,
		NegotiatedVer: TLSVersionString(policy.MinTLSVersion),
		Reason:        fmt.Sprintf("server honors %s profile (via exec probe)", policy.ProfileType),
	}
}

// IsPortTLS probes a single TCP port via openssl to determine whether it speaks TLS.
// It does not validate TLS version or cipher compliance — only whether TLS is present.
func IsPortTLS(ctx context.Context, executor checks.ProbeExecutor, probePod *corev1.Pod, address string, port int32) (isTLS, reachable bool, reason string) {
	endpoint := net.JoinHostPort(address, strconv.Itoa(int(port)))
	cmd := fmt.Sprintf("echo | timeout 5 openssl s_client -connect %s 2>&1", endpoint)
	stdout, err := execOpenSSL(ctx, executor, probePod, cmd)

	if err != nil && !hasOpensslOutput(stdout) {
		return false, false, fmt.Sprintf("exec probe failed: %v", err)
	}

	if strings.Contains(stdout, "connect:errno=") || strings.Contains(stdout, "Connection refused") {
		return false, false, reasonPortUnreachable
	}

	if !hasOpensslOutput(stdout) {
		return false, false, "no recognizable openssl output"
	}

	if strings.Contains(stdout, opensslAlertProtoVer) ||
		strings.Contains(stdout, opensslAlertHandshake) ||
		strings.Contains(stdout, opensslHandshakeFailure) {
		return true, true, "TLS server detected (handshake alert)"
	}

	if !strings.Contains(stdout, opensslCipherNone) {
		if strings.Contains(stdout, "Cipher    :") || strings.Contains(stdout, "Cipher:") {
			cipher := extractOpenSSLCipher(stdout)
			if cipher != "" && cipher != "0000" && cipher != "(NONE)" {
				return true, true, fmt.Sprintf("TLS negotiated (cipher: %s)", cipher)
			}
		}
	}

	return false, true, "plaintext service (no TLS)"
}

func hasOpensslOutput(stdout string) bool {
	return strings.Contains(stdout, opensslConnected) ||
		strings.Contains(stdout, opensslConnErrno) ||
		strings.Contains(stdout, "SSL") ||
		strings.Contains(stdout, "Cipher")
}

func opensslVersionNegotiated(stdout string, ver uint16) bool {
	verName := opensslVersionName(ver)
	return strings.Contains(stdout, "Protocol  : "+verName) ||
		strings.Contains(stdout, "Protocol: "+verName)
}

func opensslHandshakeRejected(output string) bool {
	return strings.Contains(output, opensslCipherNone) ||
		strings.Contains(output, opensslAlertProtoVer) ||
		strings.Contains(output, opensslHandshakeFailure)
}

func probeExecMinVersion(ctx context.Context, executor checks.ProbeExecutor, probePod *corev1.Pod, endpoint string, policy TLSPolicy) *TLSProbeResult {
	flag := opensslVersionFlag(policy.MinTLSVersion)
	cmd := fmt.Sprintf("echo | timeout 5 openssl s_client -connect %s %s 2>&1", endpoint, flag)
	stdout, err := execOpenSSL(ctx, executor, probePod, cmd)

	if err != nil && !hasOpensslOutput(stdout) {
		return &TLSProbeResult{
			Compliant: true,
			IsTLS:     false,
			Reachable: false,
			Reason:    fmt.Sprintf("exec probe failed: %v (stdout=%s)", err, truncate(stdout, truncateLen)),
		}
	}

	if opensslHandshakeRejected(stdout) {
		r := classifyExecNoMinVersion(stdout, policy)
		return &r
	}

	if opensslVersionNegotiated(stdout, policy.MinTLSVersion) {
		return nil
	}
	if policy.MinTLSVersion < tls.VersionTLS13 && opensslVersionNegotiated(stdout, tls.VersionTLS13) {
		return nil
	}

	r := classifyExecNoMinVersion(stdout, policy)
	return &r
}

func classifyExecNoMinVersion(stdout string, policy TLSPolicy) TLSProbeResult {
	if strings.Contains(stdout, "connect:errno=") || strings.Contains(stdout, "Connection refused") {
		return TLSProbeResult{
			Compliant: true,
			IsTLS:     false,
			Reachable: false,
			Reason:    "port unreachable via exec probe",
		}
	}

	if strings.Contains(stdout, opensslAlertProtoVer) ||
		strings.Contains(stdout, opensslAlertHandshake) ||
		strings.Contains(stdout, opensslHandshakeFailure) {
		return TLSProbeResult{
			Compliant:     false,
			IsTLS:         true,
			Reachable:     true,
			NegotiatedVer: fmt.Sprintf("< %s", TLSVersionString(policy.MinTLSVersion)),
			Reason:        fmt.Sprintf("server does not support %s via exec probe", TLSVersionString(policy.MinTLSVersion)),
		}
	}

	if !hasOpensslOutput(stdout) {
		return TLSProbeResult{
			Compliant: true,
			IsTLS:     false,
			Reachable: false,
			Reason:    fmt.Sprintf("exec probe produced no recognizable output (stdout=%s)", truncate(stdout, truncateLen)),
		}
	}

	return TLSProbeResult{
		Compliant: true,
		IsTLS:     false,
		Reachable: true,
		Reason:    "non-TLS service (informational, via exec probe)",
	}
}

func probeExecVersion(ctx context.Context, executor checks.ProbeExecutor, probePod *corev1.Pod, endpoint string, ver uint16, expectAccept bool, policy TLSPolicy) TLSProbeResult {
	flag := opensslVersionFlag(ver)
	cmd := fmt.Sprintf("echo | timeout 5 openssl s_client -connect %s %s 2>&1", endpoint, flag)
	stdout, _ := execOpenSSL(ctx, executor, probePod, cmd)

	rejected := opensslHandshakeRejected(stdout)
	accepted := !rejected && opensslVersionNegotiated(stdout, ver)

	if expectAccept && rejected {
		return TLSProbeResult{
			Compliant:     false,
			IsTLS:         true,
			Reachable:     true,
			NegotiatedVer: TLSVersionString(ver),
			Reason:        fmt.Sprintf("server rejected %s but %s profile requires support for versions %s through TLS 1.3 (via exec probe)", TLSVersionString(ver), policy.ProfileType, TLSVersionString(policy.MinTLSVersion)),
		}
	}

	if !expectAccept && accepted {
		return TLSProbeResult{
			Compliant:     false,
			IsTLS:         true,
			Reachable:     true,
			NegotiatedVer: TLSVersionString(ver),
			Reason:        fmt.Sprintf("server accepts %s (%s minimum required, via exec probe)", TLSVersionString(ver), TLSVersionString(policy.MinTLSVersion)),
		}
	}

	return TLSProbeResult{
		Compliant:     true,
		IsTLS:         true,
		Reachable:     true,
		NegotiatedVer: TLSVersionString(ver),
		Reason:        fmt.Sprintf("server correctly handles %s (via exec probe)", TLSVersionString(ver)),
	}
}

func probeExecCipherCompliance(ctx context.Context, executor checks.ProbeExecutor, probePod *corev1.Pod, endpoint string, policy TLSPolicy) *TLSProbeResult {
	if policy.MinTLSVersion > tls.VersionTLS12 {
		return nil
	}

	disallowedNames := computeDisallowedOpenSSLCiphers(policy)
	if len(disallowedNames) == 0 {
		return nil
	}

	cipherStr := strings.Join(disallowedNames, ":")
	cmd := fmt.Sprintf("echo | timeout 5 openssl s_client -connect %s -cipher %s %s 2>&1", endpoint, cipherStr, opensslFlagTLS12)
	stdout, _ := execOpenSSL(ctx, executor, probePod, cmd)

	rejected := opensslHandshakeRejected(stdout) ||
		strings.Contains(stdout, opensslNoCiphers) ||
		strings.Contains(stdout, opensslAlertHandshake)

	if rejected {
		return nil
	}

	if strings.Contains(stdout, "Cipher    :") || strings.Contains(stdout, "Cipher:") {
		cipherName := extractOpenSSLCipher(stdout)
		return &TLSProbeResult{
			Compliant:     false,
			IsTLS:         true,
			Reachable:     true,
			NegotiatedVer: tlsVersionNameTLS12,
			Reason:        fmt.Sprintf("server accepted disallowed cipher %s (not in %s profile, via exec probe)", cipherName, policy.ProfileType),
		}
	}

	return nil
}

func computeDisallowedOpenSSLCiphers(policy TLSPolicy) []string {
	allowedSet := make(map[string]bool, len(policy.AllowedCipherNames))
	for _, name := range policy.AllowedCipherNames {
		allowedSet[name] = true
	}

	var disallowed []string
	for name := range opensslToGoCipher {
		if !allowedSet[name] {
			disallowed = append(disallowed, name)
		}
	}
	return disallowed
}

func extractOpenSSLCipher(stdout string) string {
	for line := range strings.SplitSeq(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(trimmed, "Cipher    :"); ok {
			return strings.TrimSpace(after)
		}
		if after, ok := strings.CutPrefix(trimmed, "Cipher:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return reasonUnknown
}

func opensslVersionFlag(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return opensslFlagTLS10
	case tls.VersionTLS11:
		return opensslFlagTLS11
	case tls.VersionTLS12:
		return opensslFlagTLS12
	case tls.VersionTLS13:
		return opensslFlagTLS13
	default:
		return opensslFlagTLS12
	}
}

func opensslVersionName(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return opensslProtoNameTLS10
	case tls.VersionTLS11:
		return opensslProtoNameTLS11
	case tls.VersionTLS12:
		return opensslProtoNameTLS12
	case tls.VersionTLS13:
		return opensslProtoNameTLS13
	default:
		return opensslProtoNameTLS12
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
