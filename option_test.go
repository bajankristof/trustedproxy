package trustedproxy

import (
	"net/netip"
	"testing"
)

func TestNew(t *testing.T) {
	tests := map[string]struct {
		opts       []Option
		wantLen    int
		wantErr    bool
		wantPrefix string
	}{
		"no options": {
			opts:    []Option{},
			wantLen: 0,
		},
		"WithDefaults": {
			opts:    []Option{WithDefaults()},
			wantLen: len(DefaultPrefixes()),
		},
		"WithIP": {
			opts:    []Option{WithIP(netip.MustParseAddr("192.168.1.1"))},
			wantLen: 1,
		},
		"WithIPs": {
			opts: []Option{WithIPs(
				netip.MustParseAddr("192.168.1.1"),
				netip.MustParseAddr("10.0.0.1"),
			)},
			wantLen: 2,
		},
		"WithPrefix": {
			opts:       []Option{WithPrefix(netip.MustParsePrefix("192.168.0.0/16"))},
			wantLen:    1,
			wantPrefix: "192.168.0.0/16",
		},
		"WithPrefixes": {
			opts: []Option{WithPrefixes(
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("10.0.0.0/8"),
			)},
			wantLen: 2,
		},
		"WithString IPv4": {
			opts:       []Option{WithString("192.168.1.1")},
			wantLen:    1,
			wantPrefix: "192.168.1.1/32",
		},
		"WithString malformed": {
			opts:    []Option{WithString("foo")},
			wantErr: true,
		},
		"WithStrings IPv4s": {
			opts:    []Option{WithStrings("192.168.1.1", "10.0.0.0/8")},
			wantLen: 2,
		},
		"WithStrings malformed": {
			opts:    []Option{WithStrings("192.168.1.1", "foo")},
			wantErr: true,
		},
		"multiple options": {
			opts: []Option{
				WithString("192.168.1.1"),
				WithIP(netip.MustParseAddr("10.0.0.1")),
				WithPrefix(netip.MustParsePrefix("172.16.0.0/12")),
			},
			wantLen: 3,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tp, err := New(test.opts...)
			if test.wantErr {
				if err == nil {
					t.Error("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tp.prefixes) != test.wantLen {
				t.Fatalf("got %d prefixes, want %d", len(tp.prefixes), test.wantLen)
			}
			if test.wantPrefix != "" && tp.prefixes[0].String() != test.wantPrefix {
				t.Errorf("prefix: got %s, want %s", tp.prefixes[0], test.wantPrefix)
			}
		})
	}
}
