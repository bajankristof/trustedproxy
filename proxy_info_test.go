package trustedproxy

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestIsSecure(t *testing.T) {
	tests := map[string]struct {
		tls  *tls.ConnectionState
		pi   *proxyInfo
		want bool
	}{
		"no proxyInfo, no TLS":    {},
		"no proxyInfo, TLS":       {tls: &tls.ConnectionState{}, want: true},
		"proxyInfo: secure=true":  {pi: &proxyInfo{secure: true}, want: true},
		"proxyInfo: secure=false": {pi: &proxyInfo{secure: false}},
		"proxyInfo overrides TLS": {tls: &tls.ConnectionState{}, pi: &proxyInfo{secure: false}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.TLS = test.tls
			if test.pi != nil {
				r = withProxyInfo(r, test.pi)
			}
			if got := IsSecure(r); got != test.want {
				t.Errorf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestRemoteAddr(t *testing.T) {
	tests := map[string]struct {
		remoteAddr string
		pi         *proxyInfo
		want       string
	}{
		"no proxyInfo": {remoteAddr: "1.2.3.4:56789", want: "1.2.3.4:56789"},
		"with proxyInfo": {
			remoteAddr: "192.168.1.1:12345",
			pi:         &proxyInfo{remoteAddr: "1.2.3.4:0"},
			want:       "1.2.3.4:0",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = test.remoteAddr
			if test.pi != nil {
				r = withProxyInfo(r, test.pi)
			}
			if got := RemoteAddr(r); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}
