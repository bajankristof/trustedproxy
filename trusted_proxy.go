package trustedproxy

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

var defaultPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.1/32"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// DefaultPrefixes returns the default trusted proxy IP ranges:
// loopback (127.0.0.1/32, ::1/128) and private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
func DefaultPrefixes() []netip.Prefix {
	cp := make([]netip.Prefix, len(defaultPrefixes))
	copy(cp, defaultPrefixes)
	return cp
}

// TrustedProxy holds a list of trusted proxy IP prefixes.
// All methods are safe for concurrent use.
type TrustedProxy struct {
	mu       sync.RWMutex
	prefixes []netip.Prefix
}

// New creates a new TrustedProxy with the given string IP prefixes or IPs.
func New(opts ...Option) (*TrustedProxy, error) {
	tp := &TrustedProxy{}

	for _, opt := range opts {
		if err := opt(tp); err != nil {
			return nil, err
		}
	}

	return tp, nil
}

// Default creates a new TrustedProxy with the default trusted proxy IP ranges. See DefaultPrefixes.
func Default() *TrustedProxy {
	return &TrustedProxy{prefixes: DefaultPrefixes()}
}

// AddIP marks requests from the given IP address as coming from a trusted proxy.
func (tp *TrustedProxy) AddIP(ip netip.Addr) {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	tp.mu.Lock()
	defer tp.mu.Unlock()
	if ip.Is4() {
		tp.prefixes = append(tp.prefixes, netip.PrefixFrom(ip, 32))
	} else {
		tp.prefixes = append(tp.prefixes, netip.PrefixFrom(ip, 128))
	}
}

// AddPrefix marks requests from the given prefix as coming from a trusted proxy.
func (tp *TrustedProxy) AddPrefix(prefix netip.Prefix) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.prefixes = append(tp.prefixes, prefix)
}

// AddString marks requests from the given string IP prefix or IP as coming from a trusted proxy.
func (tp *TrustedProxy) AddString(s string) error {
	if !strings.Contains(s, "/") {
		if strings.Contains(s, ":") {
			s += "/128"
		} else {
			s += "/32"
		}
	}

	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return err
	}

	if prefix.Addr().Is4In6() {
		ip := prefix.Addr().Unmap()
		prefix = netip.PrefixFrom(ip, 32)
	}

	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.prefixes = append(tp.prefixes, prefix)

	return nil
}

// Check returns whether the request came from a trusted proxy
// based on the remote address of the request.
func (tp *TrustedProxy) Check(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	return tp.Contains(ip)
}

// Contains returns whether the given IP address is in the list of trusted proxies.
func (tp *TrustedProxy) Contains(ip netip.Addr) bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	tp.mu.RLock()
	defer tp.mu.RUnlock()

	return tp.contains(ip)
}

// Handler returns a handler that updates the request's RemoteAddr and URL.Scheme
// based on the X-Forwarded-For and X-Forwarded-Proto headers
// if the remote address of the request is in the list of trusted proxies
// before invoking the handler h.
func (tp *TrustedProxy) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tp.Check(r) {
			h.ServeHTTP(w, r)
			return
		}

		r = r.Clone(r.Context())

		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			if ip, ok := tp.clientIP(v); ok {
				r.RemoteAddr = net.JoinHostPort(ip.String(), "0")
			}
		}

		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			if v == "http" || v == "https" {
				r.URL.Scheme = v
			}
		}

		h.ServeHTTP(w, r)
	})
}

// contains checks if the given IP address is in the list of trusted proxies
// without acquiring the read lock.
func (tp *TrustedProxy) contains(ip netip.Addr) bool {
	for _, prefix := range tp.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// clientIP returns the real client IP from a comma-separated set of IPs
// using the rightmost non-trusted algorithm
func (tp *TrustedProxy) clientIP(h string) (netip.Addr, bool) {
	parts := strings.Split(h, ",")

	tp.mu.RLock()
	defer tp.mu.RUnlock()

	var fallback netip.Addr

	for i := len(parts) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		if ip.Is4In6() {
			ip = ip.Unmap()
		}
		fallback = ip
		if !tp.contains(ip) {
			return ip, true
		}
	}

	return fallback, fallback.IsValid()
}
