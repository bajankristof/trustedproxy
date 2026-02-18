package trustedproxy

import (
	"net/netip"
)

type Option func(*TrustedProxy) error

// WithDefaults adds the default trusted proxy IP ranges to the TrustedProxy.
// See DefaultPrefixes for the list of ranges.
func WithDefaults() Option {
	return WithPrefixes(DefaultPrefixes()...)
}

// WithIP adds the given IP address to the TrustedProxy.
func WithIP(ip netip.Addr) Option {
	return func(tp *TrustedProxy) error {
		tp.AddIP(ip)
		return nil
	}
}

// WithIPs adds the given IP addresses to the TrustedProxy.
func WithIPs(ips ...netip.Addr) Option {
	return func(tp *TrustedProxy) error {
		for _, ip := range ips {
			tp.AddIP(ip)
		}

		return nil
	}
}

// WithPrefix adds the given IP prefix to the TrustedProxy.
func WithPrefix(prefix netip.Prefix) Option {
	return func(tp *TrustedProxy) error {
		tp.AddPrefix(prefix)
		return nil
	}
}

// WithPrefixes adds the given IP prefixes to the TrustedProxy.
func WithPrefixes(prefixes ...netip.Prefix) Option {
	return func(tp *TrustedProxy) error {
		for _, prefix := range prefixes {
			tp.AddPrefix(prefix)
		}

		return nil
	}
}

// WithString adds the given string IP prefix or IP to the TrustedProxy.
func WithString(s string) Option {
	return func(tp *TrustedProxy) error {
		return tp.AddString(s)
	}
}

// WithStrings adds the given string IP prefixes or IPs to the TrustedProxy.
func WithStrings(s ...string) Option {
	return func(tp *TrustedProxy) error {
		for _, v := range s {
			if err := tp.AddString(v); err != nil {
				return err
			}
		}

		return nil
	}
}
