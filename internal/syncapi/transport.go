package syncapi

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Transport classes.
const (
	TransportLoopback = "loopback"
	TransportLAN      = "lan"
	TransportTailnet  = "tailnet"
	TransportOther    = "other"
)

// Headers Tailscale adds when it fronts a service.
const (
	// HeaderTailscaleLogin and HeaderTailscaleName are injected by `tailscale
	// serve` for requests that came from an authenticated tailnet user.
	HeaderTailscaleLogin = "Tailscale-User-Login"
	HeaderTailscaleName  = "Tailscale-User-Name"

	// HeaderFunnel is added to requests arriving through Tailscale Funnel,
	// which publishes a service to the whole internet.
	HeaderFunnel = "Tailscale-Funnel-Request"
)

// Classifier decides which network path a request took.
//
// Tailscale is network reachability, not authorisation. Knowing the path is
// still useful: it is recorded in the audit log, it lets an operator see that
// a phone is reaching home over the tailnet, and it supports the optional rule
// that tailnet traffic must additionally come from an expected tailnet user.
// None of it replaces the per-request signature.
type Classifier struct {
	LAN     []netip.Prefix
	Tailnet []netip.Prefix

	// TrustServe says the loopback listener is fronted by `tailscale serve`, so
	// Tailscale-User-* headers from a loopback peer are genuine. It must stay
	// off unless that is true: with it on and something else (a local process,
	// a different proxy) able to reach the loopback port, anyone could claim to
	// be any tailnet user.
	TrustServe bool

	// RequireIdentity makes requests that arrive by tailnet demand a Tailscale
	// identity header that matches AllowLogins.
	RequireIdentity bool
	AllowLogins     []string

	// DenyOther rejects requests from peers in neither the LAN nor the tailnet
	// ranges. Off by default because a household on IPv6 reaches its own server
	// by a global address that no LAN range lists.
	DenyOther bool
}

// DefaultLAN lists private, unique-local and link-local ranges: what "this
// network" means when the operator does not say.
func DefaultLAN() []netip.Prefix {
	return mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "fc00::/7", "fe80::/10")
}

// DefaultTailnet lists Tailscale's CGNAT range and its IPv6 ULA prefix.
func DefaultTailnet() []netip.Prefix {
	return mustPrefixes("100.64.0.0/10", "fd7a:115c:a1e0::/48")
}

func mustPrefixes(in ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// ParsePrefixes parses CIDR strings.
func ParsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// TransportInfo is the classification of one request.
type TransportInfo struct {
	Class string

	// Login is the Tailscale user, set only when it came from a trusted Serve
	// header. It is empty — never merely unverified — otherwise.
	Login string

	// Funnel is true when the request carries the Funnel marker.
	Funnel bool

	// Peer is the TCP peer, for rate limiting. Behind Serve it is loopback for
	// every caller, which is why authenticated limits key on client ID instead.
	Peer netip.Addr
}

// Classify inspects a request.
func (c *Classifier) Classify(r *http.Request) TransportInfo {
	info := TransportInfo{Class: TransportOther}

	// The Funnel marker is read whatever the peer is. It is rejected outright
	// by the caller; here it is only reported.
	info.Funnel = r.Header.Get(HeaderFunnel) != ""

	peer, ok := peerAddr(r.RemoteAddr)
	if !ok {
		return info
	}
	info.Peer = peer

	switch {
	case peer.IsLoopback():
		info.Class = TransportLoopback
		// Honoured only from loopback, and only when the operator said a Serve
		// proxy is what is connecting. From any other peer the header is just
		// text a client typed, and is never read.
		if c.TrustServe {
			if login := cleanLogin(r.Header.Get(HeaderTailscaleLogin)); login != "" {
				info.Login = login
				// Serve only injects identity for traffic that arrived over
				// the tailnet, so this request really is a tailnet request
				// even though the TCP peer is 127.0.0.1.
				info.Class = TransportTailnet
			}
		}
	case inAny(c.Tailnet, peer):
		info.Class = TransportTailnet
	case inAny(c.LAN, peer):
		info.Class = TransportLAN
	}
	return info
}

// IdentityOK applies the optional tailnet-identity rule.
//
// It binds the loopback case too when TrustServe is on: a request that reaches
// a Serve-fronted loopback port without identity headers is either a local
// process or a tagged tailnet node, and the rule cannot tell which, so it
// refuses both rather than guess. A direct tailnet peer (the listener bound to
// a tailnet address) can never present a trustworthy header and is refused
// under the rule for the same reason.
func (c *Classifier) IdentityOK(info TransportInfo) bool {
	if !c.RequireIdentity {
		return true
	}
	bound := info.Class == TransportTailnet || (info.Class == TransportLoopback && c.TrustServe)
	if !bound {
		return true
	}
	if info.Login == "" {
		return false
	}
	if len(c.AllowLogins) == 0 {
		return true
	}
	for _, a := range c.AllowLogins {
		if strings.EqualFold(a, info.Login) {
			return true
		}
	}
	return false
}

func peerAddr(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	// A zone ("fe80::1%en0") is part of the textual form, not the address.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	// A v4-mapped IPv6 peer ("::ffff:100.64.1.2") must match IPv4 ranges.
	return a.Unmap(), true
}

func inAny(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// cleanLogin keeps a login to printable ASCII, so a header value cannot carry
// control characters into logs.
func cleanLogin(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return ""
		}
	}
	return s
}

// IsLoopbackAddr reports whether a listen address binds only the loopback
// interface. An empty host (":8444") binds every interface and is not
// loopback; the same test in cairn-tsdb treats it as loopback, which is why
// this one is stricter.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}
