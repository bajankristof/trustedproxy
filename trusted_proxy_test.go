package trustedproxy

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestTrustedProxy_AddString(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    string
		wantErr bool
	}{
		"IPv4": {
			input:   "192.168.1.1",
			want:    "192.168.1.1/32",
			wantErr: false,
		},
		"IPv4 CIDR": {
			input:   "192.168.0.0/16",
			wantErr: false,
		},
		"IPv6": {
			input:   "2001:db8::1",
			want:    "2001:db8::1/128",
			wantErr: false,
		},
		"IPv6 CIDR": {
			input:   "2001:db8::/32",
			wantErr: false,
		},
		"IPv4In6": {
			input: "::ffff:192.168.1.1",
			want:  "192.168.1.1/32",
		},
		"malformed IP": {
			input:   "foo",
			wantErr: true,
		},
		"malformed CIDR": {
			input:   "foo/24",
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tp := &TrustedProxy{}

			err := tp.AddString(test.input)
			if err != nil {
				if !test.wantErr {
					t.Errorf("unexpected error: %v", err)
				}

				if len(tp.prefixes) != 0 {
					t.Fatalf("got %d prefixes, want 0", len(tp.prefixes))
				}

				return
			} else if test.wantErr {
				t.Error("want error, got nil")
			}

			if len(tp.prefixes) != 1 {
				t.Fatalf("got %d prefixes, want 1", len(tp.prefixes))
			}

			output := test.want
			if output == "" {
				output = test.input
			}

			prefix := tp.prefixes[len(tp.prefixes)-1]
			if prefix.String() != output {
				t.Errorf("prefix: got %s, want %s", prefix.String(), output)
			}
		})
	}
}

func TestTrustedProxy_AddIP(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"IPv4":    {input: "192.168.1.1", want: "192.168.1.1/32"},
		"IPv6":    {input: "2001:db8::1", want: "2001:db8::1/128"},
		"IPv4In6": {input: "::ffff:192.168.1.1", want: "192.168.1.1/32"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tp := &TrustedProxy{}
			tp.AddIP(netip.MustParseAddr(test.input))

			if len(tp.prefixes) != 1 {
				t.Fatalf("got %d prefixes, want 1", len(tp.prefixes))
			}

			if got := tp.prefixes[0].String(); got != test.want {
				t.Errorf("prefix: got %s, want %s", got, test.want)
			}
		})
	}
}

func TestTrustedProxy_AddPrefix(t *testing.T) {
	tp := &TrustedProxy{}

	prefix := netip.MustParsePrefix("192.168.1.1/32")
	tp.AddPrefix(prefix)

	if len(tp.prefixes) != 1 {
		t.Fatalf("got %d prefixes, want 1", len(tp.prefixes))
	}

	if tp.prefixes[0] != prefix {
		t.Errorf("prefix: got %s, want %s", tp.prefixes[0].String(), prefix.String())
	}
}

func TestTrustedProxy_Check(t *testing.T) {
	tests := map[string]struct {
		prefixes   []netip.Prefix
		remoteAddr string
		want       bool
	}{
		"IPv4 match": {
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			remoteAddr: "192.168.1.1",
			want:       true,
		},
		"IPv4 no match": {
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			remoteAddr: "172.16.1.1",
			want:       false,
		},
		"IPv6 match": {
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/32"),
			},
			remoteAddr: "2001:db8::1",
			want:       true,
		},
		"IPv6 no match": {
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/32"),
			},
			remoteAddr: "2001:db9::1",
			want:       false,
		},
		"IPv4In6 match": {
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			remoteAddr: "::ffff:192.168.1.1",
			want:       true,
		},
		"IPv4In6 no match": {
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			remoteAddr: "::ffff:10.0.0.1",
			want:       false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tp := &TrustedProxy{prefixes: test.prefixes}

			addr := test.remoteAddr
			if strings.Contains(addr, ":") {
				addr = "[" + addr + "]"
			}

			r := &http.Request{RemoteAddr: addr + ":12345"}

			result := tp.Check(r)
			if result != test.want {
				t.Errorf("got %v, want %v", result, test.want)
			}
		})
	}
}

func TestTrustedProxy_Contains(t *testing.T) {
	tests := map[string]struct {
		prefixes []netip.Prefix
		input    string
		want     bool
	}{
		"IPv4 match": {
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			input:    "192.168.1.1",
			want:     true,
		},
		"IPv4 no match": {
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			input:    "10.0.0.1",
			want:     false,
		},
		"IPv6 match": {
			prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			input:    "2001:db8::1",
			want:     true,
		},
		"IPv6 no match": {
			prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			input:    "2001:db9::1",
			want:     false,
		},
		"IPv4In6 match": {
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			input:    "::ffff:192.168.1.1",
			want:     true,
		},
		"IPv4In6 no match": {
			prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			input:    "::ffff:10.0.0.1",
			want:     false,
		},
		"no prefixes": {
			prefixes: nil,
			input:    "192.168.1.1",
			want:     false,
		},
		"multiple prefixes": {
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			input: "192.168.1.1",
			want:  true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tp := &TrustedProxy{prefixes: test.prefixes}
			ip := netip.MustParseAddr(test.input)
			result := tp.Contains(ip)
			if result != test.want {
				t.Errorf("got %v, want %v", result, test.want)
			}
		})
	}
}

func TestTrustedProxy_Handler(t *testing.T) {
	tests := map[string]struct {
		prefixes   []netip.Prefix
		remoteAddr string
		headers    map[string]string
		wantAddr   string
		wantScheme string
	}{
		"untrusted proxy": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Forwarded-For":   "1.2.3.4",
				"X-Forwarded-Proto": "https",
			},
			wantAddr:   "192.168.1.1:12345",
			wantScheme: "",
		},
		"trusted proxy: X-Forwarded-For single IP": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			wantAddr:   "1.2.3.4:0",
		},
		"trusted proxy: X-Forwarded-For multiple IPs uses rightmost non-trusted": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8, 9.10.11.12"},
			wantAddr:   "9.10.11.12:0",
		},
		"trusted proxy: X-Forwarded-For skips trusted IPs": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4, 192.168.2.1"},
			wantAddr:   "1.2.3.4:0",
		},
		"trusted proxy: X-Forwarded-For all trusted falls back to leftmost": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "192.168.2.1, 192.168.3.1"},
			wantAddr:   "192.168.2.1:0",
		},
		"trusted proxy: X-Forwarded-For with spaces": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "  1.2.3.4  , 5.6.7.8"},
			wantAddr:   "5.6.7.8:0",
		},
		"trusted proxy: X-Forwarded-For malformed IP": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "foo"},
			wantAddr:   "192.168.1.1:12345",
		},
		"trusted proxy: X-Forwarded-Proto": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{"X-Forwarded-Proto": "https"},
			wantAddr:   "192.168.1.1:12345",
			wantScheme: "https",
		},
		"trusted proxy: all supported headers": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Forwarded-For":   "1.2.3.4",
				"X-Forwarded-Proto": "https",
			},
			wantAddr:   "1.2.3.4:0",
			wantScheme: "https",
		},
		"trusted proxy: no headers": {
			prefixes:   []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			remoteAddr: "192.168.1.1:12345",
			headers:    map[string]string{},
			wantAddr:   "192.168.1.1:12345",
			wantScheme: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tp := &TrustedProxy{prefixes: test.prefixes}

			var gotAddr, gotScheme string
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAddr = r.RemoteAddr
				gotScheme = r.URL.Scheme
			})

			handler := tp.Handler(inner)

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			r.RemoteAddr = test.remoteAddr
			for k, v := range test.headers {
				r.Header.Set(k, v)
			}

			handler.ServeHTTP(httptest.NewRecorder(), r)

			if test.wantAddr != "" && gotAddr != test.wantAddr {
				t.Errorf("RemoteAddr: got %q, want %q", gotAddr, test.wantAddr)
			}
			if gotScheme != test.wantScheme {
				t.Errorf("URL.Scheme: got %q, want %q", gotScheme, test.wantScheme)
			}
		})
	}
}
